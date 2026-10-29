#!/usr/bin/env python3
"""
Tela Exclusiva de Identificação de Porta de Switch Gerenciável (LLDP / CDP / SNMP)
Apresenta um painel visual realista em rack 19" 1U com número de portas detectado,
indica com precisão a porta física em que o computador está conectado,
status dos links e todas as informações detalhadas de infraestrutura L2/L3.
"""
import os
import sys
from typing import Dict, Optional

from PyQt5.QtCore import QPointF, QRectF, QSize, Qt, pyqtSlot
from PyQt5.QtGui import QColor, QFont, QIcon, QKeySequence, QPixmap
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from i18n import tr
from lldp_engine import (
    LLDPPortInfo,
    LLDPSnifferWorker,
    SNMPSwitchWorker,
    get_demo_preset,
)
from scanner_engine import get_all_network_interfaces
from switch_visual_widget import SwitchFrontPanelWidget


class LLDPSwitchDialog(QDialog):
    """
    Janela Principal Exclusiva para Detecção de Portas de Switches Gerenciáveis.
    """
    def __init__(self, parent=None, gateway_ip: str = "", is_dark: bool = True):
        super().__init__(parent)
        self.is_dark = is_dark
        self.gateway_ip = gateway_ip or "192.168.1.254"
        self.current_info: Optional[LLDPPortInfo] = None

        self.sniffer_worker: Optional[LLDPSnifferWorker] = None
        self.snmp_worker: Optional[SNMPSwitchWorker] = None

        self.setWindowTitle(tr("lldp_window_title", "🔌 Identificador de Porta do Switch (LLDP / CDP / SNMP) — IP Scan IGT"))
        self.setMinimumSize(1050, 720)
        self.resize(1180, 800)

        # Configura estilo visual Dark/Light
        self._apply_styling()

        self._init_ui()
        self._load_interfaces()

        # Inicia com preset padrão demonstrativo para visualização imediata
        self.load_demo("cisco_24")

    def _apply_styling(self):
        bg = "#0b0f17" if self.is_dark else "#f3f4f6"
        fg = "#f1f5f9" if self.is_dark else "#111827"
        card_bg = "#111827" if self.is_dark else "#ffffff"
        border_col = "#1f2937" if self.is_dark else "#e5e7eb"
        btn_bg = "#1e293b" if self.is_dark else "#e2e8f0"
        btn_hover = "#2563eb"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg};
                color: {fg};
            }}
            QFrame#topToolbar {{
                background-color: {card_bg};
                border-bottom: 1px solid {border_col};
                border-radius: 6px;
                padding: 6px 10px;
            }}
            QFrame#statusBanner {{
                background-color: #172554;
                border: 1px solid #1e40af;
                border-radius: 6px;
                padding: 6px 12px;
            }}
            QFrame#infoCard {{
                background-color: {card_bg};
                border: 1px solid {border_col};
                border-radius: 8px;
                padding: 10px;
            }}
            QLabel {{
                color: {fg};
            }}
            QPushButton {{
                background-color: {btn_bg};
                color: {fg};
                border: 1px solid {border_col};
                border-radius: 4px;
                padding: 6px 14px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {btn_hover};
                color: #ffffff;
            }}
            QPushButton#primaryBtn {{
                background-color: #0284c7;
                color: #ffffff;
                font-weight: bold;
                border: none;
            }}
            QPushButton#primaryBtn:hover {{
                background-color: #0369a1;
            }}
            QComboBox, QLineEdit {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {border_col};
                border-radius: 4px;
                padding: 4px 8px;
            }}
        """)

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 10, 12, 10)
        main_layout.setSpacing(10)

        # =========================================================================
        # 1. BARRA SUPERIOR DE CONTROLES (TOOLBAR)
        # =========================================================================
        top_bar = QFrame(self)
        top_bar.setObjectName("topToolbar")
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(8, 4, 8, 4)
        tb_layout.setSpacing(10)

        # Placa de Rede
        lbl_iface = QLabel(f"<b>{tr('lldp_lbl_iface', 'Placa de Rede:')}</b>")
        tb_layout.addWidget(lbl_iface)

        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(190)
        self.combo_iface.setToolTip("Selecione a placa de rede conectada ao switch")
        tb_layout.addWidget(self.combo_iface)

        # IP do Switch / Gateway para SNMP
        lbl_sw_ip = QLabel(f"<b>{tr('lldp_lbl_switch_ip', 'IP Switch:')}</b>")
        tb_layout.addWidget(lbl_sw_ip)

        self.edit_switch_ip = QLineEdit(self.gateway_ip)
        self.edit_switch_ip.setPlaceholderText("ex: 192.168.1.254")
        self.edit_switch_ip.setFixedWidth(115)
        self.edit_switch_ip.setToolTip("Endereço IP do switch para consulta direta (SNMP / Web)")
        tb_layout.addWidget(self.edit_switch_ip)

        # Credenciais Web de Acesso ao Switch (Airoha / EcoNet / FreeRTOS)
        lbl_sw_auth = QLabel("<b>Auth:</b>")
        lbl_sw_auth.setToolTip("Credenciais de gerenciamento Web do Switch (ex: Airoha / EcoNet)")
        tb_layout.addWidget(lbl_sw_auth)

        self.edit_sw_user = QLineEdit("admin")
        self.edit_sw_user.setPlaceholderText("Usuário")
        self.edit_sw_user.setFixedWidth(70)
        self.edit_sw_user.setToolTip("Usuário Web de gerenciamento do switch (padrão: admin)")
        tb_layout.addWidget(self.edit_sw_user)

        self.edit_sw_pwd = QLineEdit("admin")
        self.edit_sw_pwd.setPlaceholderText("Senha")
        self.edit_sw_pwd.setEchoMode(QLineEdit.Password)
        self.edit_sw_pwd.setFixedWidth(70)
        self.edit_sw_pwd.setToolTip("Senha Web de gerenciamento do switch (padrão: admin)")
        tb_layout.addWidget(self.edit_sw_pwd)

        # Botão: Iniciar Escuta Passiva LLDP / CDP
        self.btn_sniff = QPushButton(tr("lldp_btn_sniff", "▶ Escutar LLDP"))
        self.btn_sniff.setObjectName("primaryBtn")
        self.btn_sniff.setToolTip("Escuta pacotes multicast L2 periódicos transmitidos pelo switch na rede local")
        self.btn_sniff.clicked.connect(self.toggle_sniffer)
        tb_layout.addWidget(self.btn_sniff)

        # Botão: Consulta Ativa via SNMP
        self.btn_snmp = QPushButton(tr("lldp_btn_snmp", "🔍 Consultar Switch"))
        self.btn_snmp.setToolTip("Consulta o switch diretamente via SNMPv1/v2c e API Web (Airoha/EcoNet/FreeRTOS)")
        self.btn_snmp.clicked.connect(self.run_snmp_audit)
        tb_layout.addWidget(self.btn_snmp)

        # Botão com Menu: Modos de Demonstração (Presets de Switches)
        self.btn_demo = QToolButton()
        self.btn_demo.setText(tr("lldp_btn_demo", "✨ Testar Switch Simulado ▾"))
        self.btn_demo.setPopupMode(QToolButton.InstantPopup)
        self.btn_demo.setToolTip("Visualizar o painel em ação com perfis reais de switches Cisco, Ubiquiti, MikroTik, Aruba e Airoha")

        demo_menu = QMenu(self.btn_demo)
        act_cisco = demo_menu.addAction("🏢 Cisco Catalyst 2960X (24 Portas GbE — Porta 12)")
        act_cisco.triggered.connect(lambda: self.load_demo("cisco_24"))

        act_airoha = demo_menu.addAction("⚡ Airoha EN8851 24GE Smart Switch (Porta 16 Conectada / Porta 1 Uplink)")
        act_airoha.triggered.connect(lambda: self.load_demo("airoha_24"))

        act_unifi = demo_menu.addAction("📶 Ubiquiti UniFi Pro PoE (48 Portas GbE — Porta 7)")
        act_unifi.triggered.connect(lambda: self.load_demo("unifi_48"))

        act_mikrotik = demo_menu.addAction("🌐 MikroTik CRS326 (24 Portas GbE — Porta 3)")
        act_mikrotik.triggered.connect(lambda: self.load_demo("mikrotik_24"))

        act_aruba = demo_menu.addAction("💼 HP Aruba 2530 (8 Portas GbE — Porta 4)")
        act_aruba.triggered.connect(lambda: self.load_demo("aruba_8"))

        self.btn_demo.setMenu(demo_menu)
        tb_layout.addWidget(self.btn_demo)

        tb_layout.addStretch(1)

        # Seletor Manual de Quantidade de Portas
        lbl_ports = QLabel(tr("lldp_lbl_ports", "Portas:"))
        tb_layout.addWidget(lbl_ports)

        self.combo_ports = QComboBox()
        self.combo_ports.addItems(["Auto", "8 Portas", "16 Portas", "24 Portas", "48 Portas"])
        self.combo_ports.setCurrentText("Auto")
        self.combo_ports.currentIndexChanged.connect(self._on_ports_override)
        tb_layout.addWidget(self.combo_ports)

        main_layout.addWidget(top_bar)

        # =========================================================================
        # 2. BANNER DE STATUS E FEEDBACK EM TEMPO REAL
        # =========================================================================
        self.status_banner = QFrame(self)
        self.status_banner.setObjectName("statusBanner")
        sb_layout = QHBoxLayout(self.status_banner)
        sb_layout.setContentsMargins(10, 6, 10, 6)

        self.lbl_status = QLabel("● Pronto. Clique em 'Escutar LLDP / CDP' ou 'Consultar SNMP' para identificar o switch.")
        self.lbl_status.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.lbl_status.setStyleSheet("color: #60a5fa;")
        sb_layout.addWidget(self.lbl_status)

        sb_layout.addStretch(1)

        self.lbl_protocol_badge = QLabel("Protocolo: LLDP (IEEE 802.1AB)")
        self.lbl_protocol_badge.setStyleSheet(
            "background-color: #1e3a8a; color: #93c5fd; padding: 2px 8px; border-radius: 4px; font-weight: bold;"
        )
        sb_layout.addWidget(self.lbl_protocol_badge)

        main_layout.addWidget(self.status_banner)

        # =========================================================================
        # 3. WIDGET VISUAL: PAINEL FRONTAL DO SWITCH (1U RACKMOUNT)
        # =========================================================================
        self.switch_widget = SwitchFrontPanelWidget(self, is_dark=self.is_dark)
        self.switch_widget.port_clicked.connect(self._on_port_clicked)
        main_layout.addWidget(self.switch_widget, 0)

        # Legenda Visual do Painel
        legend_frame = QFrame(self)
        leg_layout = QHBoxLayout(legend_frame)
        leg_layout.setContentsMargins(6, 2, 6, 2)
        leg_layout.setSpacing(16)

        leg_layout.addStretch(1)
        leg_items = [
            ("📍", "#00e5ff", "Sua Conexão Local (Identificada)"),
            ("●", "#10b981", "Porta com Link Ativo (UP)"),
            ("○", "#4b5563", "Porta Sem Link (DOWN)"),
            ("🔲", "#38bdf8", "Uplink SFP/SFP+ (Fibra)"),
        ]
        for icon_s, col, label_s in leg_items:
            lbl = QLabel(f"<span style='color:{col}; font-size:13px;'><b>{icon_s}</b></span> {label_s}")
            lbl.setFont(QFont("Segoe UI", 8))
            leg_layout.addWidget(lbl)
        leg_layout.addStretch(1)

        main_layout.addWidget(legend_frame)

        # =========================================================================
        # 4. CARDS DE INFORMAÇÕES DETALHADAS (GRID INFERIOR)
        # =========================================================================
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        # CARD 1: DADOS DO SWITCH (CHASSIS / HARDWARE)
        self.card_switch = self._create_card("🏢 Switch & Fabricante", [
            ("Nome do Switch:", "lbl_sw_name", "SW-CORE-DISTRIB-01"),
            ("Modelo / SO:", "lbl_sw_model", "Cisco Catalyst 2960X-24TD-L"),
            ("Fabricante:", "lbl_sw_vendor", "Cisco Systems"),
            ("IP de Gerência:", "lbl_sw_mgmt_ip", "192.168.111.250"),
            ("MAC Chassis ID:", "lbl_sw_chassis_mac", "00:2a:6a:12:34:00"),
            ("Recursos:", "lbl_sw_caps", "Bridge (Switch L2), Router (L3)"),
        ])
        cards_layout.addWidget(self.card_switch)

        # CARD 2: DADOS DA PORTA LOCAL CONECTADA
        self.card_port = self._create_card("🔌 Porta Local Identificada", [
            ("Porta Física:", "lbl_port_id", "GigabitEthernet1/0/12"),
            ("Número no Painel:", "lbl_port_num", "Porta 12"),
            ("Descrição da Porta:", "lbl_port_desc", "Workstation Icaro / TI Infra"),
            ("VLAN Nativa (PVID):", "lbl_port_vlan", "VLAN 10 (VLAN_DADOS_CORP)"),
            ("Velocidade / Duplex:", "lbl_port_speed", "1000 Mbps Full-Duplex"),
            ("PoE (Power over Eth):", "lbl_port_poe", "802.3at PoE+ (Disponível 30W)"),
        ])
        cards_layout.addWidget(self.card_port)

        # CARD 3: DIAGNÓSTICO & AUDITORIA
        self.card_diag = self._create_card("📊 Diagnóstico da Conexão", [
            ("Protocolo Utilizado:", "lbl_diag_proto", "LLDP (IEEE 802.1AB)"),
            ("Interface Local:", "lbl_diag_iface", "enp7s0"),
            ("MAC Local (PC):", "lbl_diag_local_mac", "00:23:09:02:cd:9f"),
            ("TTL do Anúncio:", "lbl_diag_ttl", "120 segundos"),
            ("Horário da Captura:", "lbl_diag_time", "--:--:--"),
            ("Portas Ativas:", "lbl_diag_ports_summary", "8 de 24 portas ativas (33%)"),
        ])
        cards_layout.addWidget(self.card_diag)

        main_layout.addLayout(cards_layout, 1)

        # =========================================================================
        # 5. BARRA INFERIOR DE AÇÕES
        # =========================================================================
        bottom_bar = QHBoxLayout()
        bottom_bar.setContentsMargins(4, 4, 4, 4)

        self.btn_copy = QPushButton(tr("lldp_btn_copy", "📋 Copiar Relatório Técnico"))
        self.btn_copy.setToolTip("Copia as informações do switch e da porta conectada para a área de transferência")
        self.btn_copy.clicked.connect(self.copy_report_to_clipboard)
        bottom_bar.addWidget(self.btn_copy)

        self.btn_save_img = QPushButton(tr("lldp_btn_save_img", "💾 Salvar Imagem do Switch (PNG)"))
        self.btn_save_img.setToolTip("Exporta o painel frontal gráfico do switch como imagem PNG em alta resolução")
        self.btn_save_img.clicked.connect(self.save_switch_image)
        bottom_bar.addWidget(self.btn_save_img)

        bottom_bar.addStretch(1)

        self.btn_close = QPushButton(tr("btn_close", "Fechar"))
        self.btn_close.clicked.connect(self.close)
        bottom_bar.addWidget(self.btn_close)

        main_layout.addLayout(bottom_bar)

    def _create_card(self, title: str, fields: list) -> QFrame:
        """Cria um card moderno estilizado com título e pares Chave/Valor."""
        card = QFrame(self)
        card.setObjectName("infoCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        lbl_title = QLabel(f"<b>{title}</b>")
        lbl_title.setFont(QFont("Segoe UI", 10, QFont.Bold))
        lbl_title.setStyleSheet("color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 4px;")
        layout.addWidget(lbl_title)

        grid = QGridLayout()
        grid.setContentsMargins(0, 4, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(4)

        for row, (k, attr_name, default_v) in enumerate(fields):
            lbl_k = QLabel(k)
            lbl_k.setFont(QFont("Segoe UI", 8, QFont.Normal))
            lbl_k.setStyleSheet("color: #94a3b8;")

            lbl_v = QLabel(default_v)
            lbl_v.setFont(QFont("Segoe UI", 8, QFont.Bold if "lbl_port_id" in attr_name else QFont.Normal))
            lbl_v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            setattr(self, attr_name, lbl_v)

            grid.addWidget(lbl_k, row, 0, Qt.AlignLeft)
            grid.addWidget(lbl_v, row, 1, Qt.AlignLeft)

        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        layout.addStretch(1)
        return card

    def _load_interfaces(self):
        """Carrega placas de rede disponíveis no sistema."""
        self.combo_iface.clear()
        try:
            ifaces = get_all_network_interfaces()
            selected_idx = 0
            idx = 0
            for iface in ifaces:
                name = iface.get("name", "")
                ip = iface.get("ip", "")
                mac = iface.get("mac", "")
                is_loopback = iface.get("is_loopback", False)
                if is_loopback:
                    continue
                display = f"{name} ({ip})" if ip else name
                self.combo_iface.addItem(display, iface)
                # Seleciona preferencialmente a placa com IP ativo
                if ip and not ip.startswith("127."):
                    selected_idx = idx
                idx += 1
            if self.combo_iface.count() > 0:
                self.combo_iface.setCurrentIndex(selected_idx)
        except Exception:
            self.combo_iface.addItem("enp7s0 (192.168.111.46)", {"name": "enp7s0", "ip": "192.168.111.46"})

    def _get_current_iface_name(self) -> str:
        data = self.combo_iface.currentData()
        if isinstance(data, dict):
            return data.get("name", "")
        txt = self.combo_iface.currentText()
        return txt.split(" ")[0].strip()

    def _get_current_local_mac(self) -> str:
        data = self.combo_iface.currentData()
        if isinstance(data, dict):
            return data.get("mac", "")
        return ""

    def load_demo(self, preset_key: str):
        """Carrega e exibe um perfil de demonstração no painel visual."""
        info = get_demo_preset(preset_key)
        info.interface_name = self._get_current_iface_name()
        local_mac = self._get_current_local_mac()
        if local_mac:
            info.local_mac = local_mac

        self.display_port_info(info)
        self.lbl_status.setText(
            f"✓ Modo Demonstração: Exibindo {info.switch_model} conectado na porta {info.port_number}."
        )
        self.lbl_status.setStyleSheet("color: #10b981;")

    def display_port_info(self, info: LLDPPortInfo):
        """Atualiza o painel visual e todos os cards informativos."""
        self.current_info = info

        # 1. Atualiza o componente visual do switch
        self.switch_widget.set_switch_data(
            total_ports=info.total_ports,
            connected_port=info.port_number,
            connected_port_name=info.port_id or f"Porta {info.port_number}",
            switch_brand=info.switch_vendor or "SWITCH GERENCIÁVEL",
            switch_model=info.switch_model or f"{info.total_ports}-Port Gigabit Switch",
            port_status_map=info.port_status_map,
        )

        # 2. Atualiza Card do Switch
        self.lbl_sw_name.setText(info.switch_name or "Desconhecido")
        self.lbl_sw_model.setText(info.switch_model or "Switch Gerenciável")
        self.lbl_sw_vendor.setText(info.switch_vendor or "Desconhecido")
        self.lbl_sw_mgmt_ip.setText(info.management_ip or "Não anunciado")
        self.lbl_sw_chassis_mac.setText(info.chassis_id or "--:--:--:--:--:--")
        self.lbl_sw_caps.setText(", ".join(info.capabilities) if info.capabilities else "Bridge (Switch L2)")

        # 3. Atualiza Card da Porta Local
        p_name = info.port_id or f"Porta {info.port_number}"
        self.lbl_port_id.setText(f"<span style='color:#00e5ff; font-size:11px;'><b>{p_name}</b></span>")
        self.lbl_port_num.setText(f"Porta {info.port_number}" if info.port_number > 0 else "Não detectada")
        self.lbl_port_desc.setText(info.port_description or "Conexão de Estação")

        vlan_txt = f"VLAN {info.vlan_id}" if info.vlan_id > 0 else "Padrão / Desconhecida"
        if info.vlan_name:
            vlan_txt += f" ({info.vlan_name})"
        self.lbl_port_vlan.setText(vlan_txt)

        self.lbl_port_speed.setText(info.duplex_speed or "1000 Mbps Full-Duplex (Auto-MDIX)")
        self.lbl_port_poe.setText(info.poe_info or "Não aplicável")

        # 4. Atualiza Card de Diagnóstico
        self.lbl_diag_proto.setText(info.protocol or "LLDP")
        self.lbl_protocol_badge.setText(f"Protocolo: {info.protocol or 'LLDP'}")
        self.lbl_diag_iface.setText(info.interface_name or self._get_current_iface_name())
        self.lbl_diag_local_mac.setText(info.local_mac or self._get_current_local_mac() or "--:--:--:--:--:--")
        self.lbl_diag_ttl.setText(f"{info.ttl} segundos" if info.ttl else "Indefinido")
        self.lbl_diag_time.setText(info.capture_time or "--:--:--")

        up_count = sum(1 for st in info.port_status_map.values() if st in ["up", "connected"])
        pct = int((up_count * 100) / max(1, info.total_ports))
        self.lbl_diag_ports_summary.setText(f"{up_count} de {info.total_ports} portas ativas ({pct}%)")

    def toggle_sniffer(self):
        """Inicia ou interrompe a captura passiva L2 de pacotes LLDP/CDP."""
        if self.sniffer_worker and self.sniffer_worker.isRunning():
            self.sniffer_worker.stop()
            self.sniffer_worker.wait(1000)
            self.sniffer_worker = None
            self.btn_sniff.setText(tr("lldp_btn_sniff", "▶ Escutar LLDP / CDP"))
            self.lbl_status.setText("● Escuta de pacotes L2 interrompida pelo usuário.")
            self.lbl_status.setStyleSheet("color: #94a3b8;")
            return

        iface_name = self._get_current_iface_name()
        self.btn_sniff.setText(tr("lldp_btn_sniff_stop", "⏹ Parar Escuta"))
        self.lbl_status.setText(f"● Escutando na placa '{iface_name}' por anúncios multicast LLDP/CDP...")
        self.lbl_status.setStyleSheet("color: #38bdf8;")

        self.sniffer_worker = LLDPSnifferWorker(interface=iface_name, timeout_sec=45)
        self.sniffer_worker.packet_captured.connect(self._on_packet_captured)
        self.sniffer_worker.status_updated.connect(self._on_sniffer_status)
        self.sniffer_worker.error_occurred.connect(self._on_sniffer_error)
        self.sniffer_worker.finished.connect(self._on_sniffer_finished)
        self.sniffer_worker.start()

    @pyqtSlot(object)
    def _on_packet_captured(self, info: LLDPPortInfo):
        info.local_mac = self._get_current_local_mac()
        self.display_port_info(info)
        self.lbl_status.setText(
            f"✓ Sucesso! Switch '{info.switch_name or info.switch_model}' identificado na porta {info.port_id}."
        )
        self.lbl_status.setStyleSheet("color: #10b981;")

    @pyqtSlot(str)
    def _on_sniffer_status(self, msg: str):
        self.lbl_status.setText(f"● {msg}")

    @pyqtSlot(str)
    def _on_sniffer_error(self, err: str):
        self.lbl_status.setText(f"⚠️ {err.splitlines()[0]}")
        self.lbl_status.setStyleSheet("color: #f87171;")

        if err.startswith("WINDOWS_NO_AF_PACKET"):
            self.lbl_status.setText("● Alternando automaticamente para identificação via SNMP...")
            self.run_snmp_audit()
        elif "CAP_NET_RAW" in err or "Permissão L2 negada" in err:
            self._show_l2_permission_helper(err)
        else:
            QMessageBox.warning(self, "Aviso de Captura L2", err)

    def _show_l2_permission_helper(self, err: str):
        """Exibe janela orientativa e interativa quando permissões L2 forem necessárias no Linux."""
        from lldp_engine import find_l2_sniffer_binary
        sniffer_bin = find_l2_sniffer_binary()
        if not sniffer_bin:
            sniffer_bin = os.path.expanduser("~/.local/bin/ipscan-l2-sniffer")

        target_bin = sniffer_bin
        cmd_sudo = f"sudo setcap cap_net_raw,cap_net_admin+eip {target_bin}"

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("⚡ Permissão de Rede L2 Necessária — IP Scan IGT")
        msg.setText(
            "<b>A escuta passiva de pacotes Ethernet (LLDP / CDP) requer permissão de rede no Linux.</b><br><br>"
            "Por segurança, o kernel do Linux restringe o acesso a Raw Sockets para usuários comuns, "
            f"a menos que o auxiliar nativo (<code>{os.path.basename(target_bin)}</code>) possua a capacidade <code>CAP_NET_RAW</code> concedida.<br><br>"
            "<b>Como você prefere proceder?</b>"
        )

        btn_snmp = msg.addButton("🔍 Usar Consulta SNMP (Sem Root)", QMessageBox.AcceptRole)
        btn_polkit = msg.addButton("⚡ Conceder Permissão Definitiva (Polkit)", QMessageBox.ActionRole)
        btn_copy = msg.addButton("📋 Copiar Comando Terminal", QMessageBox.ActionRole)
        btn_cancel = msg.addButton("Fechar", QMessageBox.RejectRole)

        msg.exec_()
        clicked = msg.clickedButton()

        if clicked == btn_snmp:
            self.run_snmp_audit()
        elif clicked == btn_polkit:
            self._grant_cap_via_polkit(target_bin)
        elif clicked == btn_copy:
            QApplication.clipboard().setText(cmd_sudo)
            QMessageBox.information(
                self,
                "Comando Copiado",
                f"O comando abaixo foi copiado para a Área de Transferência:\n\n{cmd_sudo}\n\n"
                "Abra o terminal, cole e execute com sua senha de administrador.",
            )

    def _grant_cap_via_polkit(self, target_bin: str):
        """Tenta executar 'setcap' usando pkexec com prompt de autenticação gráfica."""
        if not os.path.exists("/usr/bin/pkexec"):
            QMessageBox.warning(
                self,
                "Polkit Indisponível",
                "O utilitário 'pkexec' não foi encontrado. Por favor, execute o comando manualmente no terminal.",
            )
            return

        setcap_path = "/usr/sbin/setcap"
        if not os.path.exists(setcap_path):
            import shutil
            setcap_path = shutil.which("setcap") or "setcap"

        self.lbl_status.setText("● Solicitando permissão via Polkit...")
        self.lbl_status.setStyleSheet("color: #38bdf8;")

        try:
            import subprocess
            res = subprocess.run(
                ["pkexec", setcap_path, "cap_net_raw,cap_net_admin+eip", target_bin],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=45,
            )
            if res.returncode == 0:
                QMessageBox.information(
                    self,
                    "Permissão Concedida!",
                    f"Permissão CAP_NET_RAW concedida com sucesso para:\n{target_bin}\n\nIniciando escuta LLDP/CDP agora...",
                )
                self.toggle_sniffer()
            else:
                err_msg = res.stderr.strip() or "Operação cancelada pelo usuário."
                self.lbl_status.setText(f"⚠️ {err_msg}")
                self.lbl_status.setStyleSheet("color: #f87171;")
        except Exception as ex:
            QMessageBox.warning(self, "Falha na Elevação", f"Erro ao executar pkexec: {ex}")

    def _on_sniffer_finished(self):
        self.btn_sniff.setText(tr("lldp_btn_sniff", "▶ Escutar LLDP / CDP"))

    def run_snmp_audit(self):
        """Inicia a consulta ativa via SNMP / Web ao IP do switch."""
        sw_ip = self.edit_switch_ip.text().strip()
        sw_user = self.edit_sw_user.text().strip() if hasattr(self, "edit_sw_user") else "admin"
        sw_pwd = self.edit_sw_pwd.text().strip() if hasattr(self, "edit_sw_pwd") else "admin"

        if not sw_ip:
            QMessageBox.information(self, "IP do Switch", "Por favor, informe o endereço IP do switch gerenciável.")
            return

        iface_name = self._get_current_iface_name()
        local_mac = self._get_current_local_mac()

        self.lbl_status.setText(f"● Consultando switch em {sw_ip} via SNMP / Web API...")
        self.lbl_status.setStyleSheet("color: #38bdf8;")

        self.snmp_worker = SNMPSwitchWorker(
            switch_ip=sw_ip,
            community="public",
            local_mac=local_mac,
            interface=iface_name,
            username=sw_user,
            password=sw_pwd,
        )
        self.snmp_worker.switch_audited.connect(self._on_snmp_success)
        self.snmp_worker.status_updated.connect(self._on_sniffer_status)
        self.snmp_worker.error_occurred.connect(self._on_snmp_error)
        self.snmp_worker.start()

    @pyqtSlot(object)
    def _on_snmp_success(self, info: LLDPPortInfo):
        self.display_port_info(info)
        self.lbl_status.setText(
            f"✓ Auditoria SNMP concluída! Switch identificado na porta {info.port_id}."
        )
        self.lbl_status.setStyleSheet("color: #10b981;")

    @pyqtSlot(str)
    def _on_snmp_error(self, err: str):
        self.lbl_status.setText(f"⚠️ {err.splitlines()[0]}")
        self.lbl_status.setStyleSheet("color: #f87171;")
        QMessageBox.warning(self, "Falha na Consulta SNMP", err)

    def _on_port_clicked(self, port_num: int):
        """Ao clicar em qualquer porta no painel, exibe os detalhes daquela porta específica."""
        if not self.current_info:
            return

        is_connected = (port_num == self.current_info.port_number)
        status = self.current_info.port_status_map.get(port_num, "down")

        prefix = "GigabitEthernet1/0/" if "cisco" in (self.current_info.switch_vendor or "").lower() else "Port "
        port_name = f"{prefix}{port_num}"

        if is_connected:
            self.lbl_port_id.setText(f"<span style='color:#00e5ff; font-size:11px;'><b>📍 {port_name} (SUA CONEXÃO)</b></span>")
            self.lbl_port_num.setText(f"Porta {port_num} (Conectada)")
            self.lbl_port_desc.setText(self.current_info.port_description or "Conexão Ativa Local")
        elif status == "up":
            self.lbl_port_id.setText(f"<span style='color:#10b981;'><b>{port_name} (Link Ativo)</b></span>")
            self.lbl_port_num.setText(f"Porta {port_num}")
            self.lbl_port_desc.setText("Dispositivo de Rede Conectado")
        else:
            self.lbl_port_id.setText(f"<span style='color:#94a3b8;'><b>{port_name} (Sem Link)</b></span>")
            self.lbl_port_num.setText(f"Porta {port_num}")
            self.lbl_port_desc.setText("Porta Desconectada / Inativa")

    def _on_ports_override(self, index: int):
        txt = self.combo_ports.currentText()
        if "8" in txt:
            self.switch_widget.set_total_ports(8)
        elif "16" in txt:
            self.switch_widget.set_total_ports(16)
        elif "24" in txt:
            self.switch_widget.set_total_ports(24)
        elif "48" in txt:
            self.switch_widget.set_total_ports(48)

    def copy_report_to_clipboard(self, show_popup: bool = True):
        """Copia um relatório técnico formatado para a área de transferência."""
        if not self.current_info:
            if show_popup:
                QMessageBox.information(self, "Aviso", "Nenhum dado de switch disponível para copiar.")
            return

        info = self.current_info
        text = f"""# RELATÓRIO DE AUDITORIA DE PORTA DE SWITCH (LLDP / CDP / SNMP)
Gerado por: IP Scan IGT
Data/Hora: {info.capture_time or 'N/A'}

--- DADOS DO EQUIPAMENTO / SWITCH ---
• Nome do Switch (SysName): {info.switch_name or 'N/A'}
• Modelo de Hardware (SysDescr): {info.switch_model or 'N/A'}
• Fabricante: {info.switch_vendor or 'N/A'}
• IP de Gerenciamento: {info.management_ip or 'N/A'}
• MAC Chassis ID: {info.chassis_id or 'N/A'}
• Capacidades Ativas: {', '.join(info.capabilities) if info.capabilities else 'Switch L2'}
• Total de Portas: {info.total_ports} portas

--- PORTA IDENTIFICADA (CONEXÃO LOCAL) ---
• Porta Física: {info.port_id or f'Porta {info.port_number}'}
• Número no Painel: Porta {info.port_number}
• Descrição da Porta: {info.port_description or 'N/A'}
• VLAN Nativa (PVID): VLAN {info.vlan_id} {f'({info.vlan_name})' if info.vlan_name else ''}
• Velocidade & Duplex: {info.duplex_speed or '1000 Mbps Full-Duplex'}
• Suporte PoE: {info.poe_info or 'N/A'}

--- DIAGNÓSTICO DA CAPTURA ---
• Protocolo Utilizado: {info.protocol}
• Interface Local Utilizada: {info.interface_name}
• MAC da Estação Local: {info.local_mac}
• TTL do Anúncio: {info.ttl}s
"""
        QApplication.clipboard().setText(text)
        if show_popup:
            QMessageBox.information(self, "Copiado", "Relatório técnico copiado com sucesso para a Área de Transferência!")

    def save_switch_image(self):
        """Renderiza e salva o painel gráfico do switch como arquivo PNG."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Painel do Switch",
            f"switch_panel_{self.current_info.port_number if self.current_info else 'porta'}.png",
            "Imagens PNG (*.png)",
        )
        if not file_path:
            return

        pixmap = QPixmap(self.switch_widget.size())
        self.switch_widget.render(pixmap)
        if pixmap.save(file_path, "PNG"):
            QMessageBox.information(self, "Imagem Salva", f"Painel do switch exportado com sucesso em:\n{file_path}")
        else:
            QMessageBox.warning(self, "Erro", "Falha ao salvar a imagem do switch.")

    def closeEvent(self, event):
        """Encerra threads ativas ao fechar a janela."""
        if self.sniffer_worker and self.sniffer_worker.isRunning():
            self.sniffer_worker.stop()
            self.sniffer_worker.wait(500)
        if self.snmp_worker and self.snmp_worker.isRunning():
            self.snmp_worker.wait(500)
        event.accept()
