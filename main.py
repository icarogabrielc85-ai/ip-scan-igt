#!/usr/bin/env python3
import concurrent.futures
import csv
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional

# Ensure package directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"

if IS_WINDOWS:
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("igt.ipscan.scanner.v2")
    except Exception:
        pass

# Verificação e Auto-Instalação Automática do PyQt5 se ausente
try:
    import PyQt5
except ImportError:
    print("[*] PyQt5 não encontrado no sistema. Instalando automaticamente...")
    try:
        pip_cmd = [sys.executable, "-m", "pip", "install", "PyQt5>=5.15.9"]
        if not IS_WINDOWS:
            pip_cmd.extend(["--break-system-packages", "--user"])
        subprocess.check_call(pip_cmd)
        import PyQt5
        print("[OK] PyQt5 instalado com sucesso!")
    except Exception as err:
        print(f"[ERRO] Não foi possível instalar o PyQt5 automaticamente: {err}")
        print("Instale manualmente executando: pip install PyQt5>=5.15.9")
        sys.exit(1)


def get_resource_path(filename: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, filename)


def open_smb(ip: str):
    if IS_WINDOWS:
        try:
            os.startfile(f"\\\\{ip}")
        except Exception:
            subprocess.Popen(["explorer.exe", f"\\\\{ip}"])
    else:
        QDesktopServices.openUrl(QUrl(f"smb://{ip}/"))


def open_terminal_ping(ip: str):
    if IS_WINDOWS:
        subprocess.Popen(f'cmd.exe /c start "Ping {ip}" cmd.exe /k ping -t {ip}', shell=True)
    else:
        terms = ["x-terminal-emulator", "konsole", "gnome-terminal", "xfce4-terminal", "xterm"]
        for t in terms:
            p = shutil.which(t)
            if p:
                if "gnome-terminal" in t:
                    subprocess.Popen([p, "--", "ping", ip])
                else:
                    subprocess.Popen([p, "-e", f"ping {ip}"])
                return
        subprocess.Popen(["xterm", "-e", f"ping {ip}"])

from PyQt5.QtCore import QObject, QPoint, QSize, Qt, QThread, QTimer, QUrl, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor, QDesktopServices, QFont, QIcon
from PyQt5.QtWidgets import (
    QAction,
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
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oui_db import OUI_DB
from scanner_engine import (
    HostRecord,
    ResourceItem,
    build_resources_for_host,
    classify_device,
    get_all_network_interfaces,
    get_local_network_info,
    probe_ping,
    read_linux_arp_table,
    scan_single_ip,
)
from onvif_engine import discover_onvif_devices, probe_rtsp
from nmap_engine import is_nmap_available, get_nmap_path
from nmap_dialog import NmapDialog
from interface_dialog import NetworkInterfaceDialog
from ui_theme import DARK_STYLESHEET, LIGHT_STYLESHEET, LivePingOscilloscope

FAVORITES_FILE = os.path.expanduser("~/.config/linux-ipscan/favorites.json")


class ScanWorker(QThread):
    host_found = pyqtSignal(object)
    progress_updated = pyqtSignal(int, int, str)
    scan_finished = pyqtSignal(int, float)

    def __init__(self, ip_list: List[str], local_info: Dict[str, str], enable_onvif: bool = True, max_workers: int = 64):
        super().__init__()
        self.ip_list = ip_list
        self.local_info = local_info
        self.enable_onvif = enable_onvif
        self.max_workers = max_workers
        self._is_running = True

    def stop(self):
        self._is_running = False

    def run(self):
        start_time = time.time()
        arp_cache = read_linux_arp_table()

        onvif_cache = {}
        if self.enable_onvif:
            self.progress_updated.emit(0, len(self.ip_list), "Buscando câmeras ONVIF (WS-Discovery)...")
            try:
                onvif_cache = discover_onvif_devices(timeout=1.2)
            except Exception as e:
                print(f"ONVIF discovery error: {e}")

        found_count = 0
        total = len(self.ip_list)
        processed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {
                executor.submit(scan_single_ip, ip, arp_cache, self.local_info, onvif_cache): ip
                for ip in self.ip_list
            }

            for future in concurrent.futures.as_completed(future_to_ip):
                if not self._is_running:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                processed += 1
                ip = future_to_ip[future]
                try:
                    record = future.result()
                    if record and record.alive:
                        found_count += 1
                        self.host_found.emit(record)
                except Exception as ex:
                    print(f"Error scanning {ip}: {ex}")

                self.progress_updated.emit(processed, total, ip)

        elapsed = time.time() - start_time
        self.scan_finished.emit(found_count, elapsed)


class LivePingWorker(QThread):
    sample_ready = pyqtSignal(str, float, int, str)

    def __init__(self):
        super().__init__()
        self._is_running = True
        self.target_ip = ""
        self._lock = threading.Lock()

    def set_target(self, ip: str):
        with self._lock:
            self.target_ip = ip

    def stop(self):
        self._is_running = False

    def run(self):
        while self._is_running:
            ip = ""
            with self._lock:
                ip = self.target_ip
            if ip:
                alive, rtt, ttl, method = probe_ping(ip, timeout_ms=500)
                if ip == self.target_ip:
                    self.sample_ready.emit(ip, rtt if alive else -1.0, ttl, method)
            time.sleep(0.50)


class PingSweepWorker(QThread):
    batch_finished = pyqtSignal(list)

    def __init__(self, ips: List[str]):
        super().__init__()
        self.ips = ips

    def run(self):
        def ping_one(ip_addr):
            alive, rtt, _, _ = probe_ping(ip_addr, timeout_ms=250)
            return ip_addr, rtt if alive else -1.0

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(self.ips) or 1)) as ex:
            for ip, rtt in ex.map(ping_one, self.ips):
                results.append((ip, rtt))
        self.batch_finished.emit(results)


def ip_sort_tuple(ip_str: str) -> tuple:
    try:
        parts = [int(p) for p in str(ip_str).strip().split(".")]
        if len(parts) == 4:
            return tuple(parts)
    except Exception:
        pass
    return (999, 999, 999, 999)


class DeviceTreeWidgetItem(QTreeWidgetItem):
    def __lt__(self, other):
        # Prevent comparing parent with child
        if self.parent() != other.parent():
            return False

        # If comparing children under the same parent, preserve or sort by text
        if self.parent() is not None:
            return self.text(1).lower() < other.text(1).lower()

        tree = self.treeWidget()
        col = tree.sortColumn() if tree else 2

        # Col 0: Status (Online ● before Offline ○)
        if col == 0:
            s1 = self.data(0, Qt.UserRole)
            s2 = other.data(0, Qt.UserRole)
            v1 = s1 if s1 is not None else (1 if self.text(0) == "●" else 0)
            v2 = s2 if s2 is not None else (1 if other.text(0) == "●" else 0)
            return v1 < v2

        # Col 1: Nome (Hostname / Device Name)
        elif col == 1:
            return self.text(1).lower() < other.text(1).lower()

        # Col 2: IP (Numeric IPv4 sorting)
        elif col == 2:
            ip1 = self.data(2, Qt.UserRole) or self.text(2)
            ip2 = other.data(2, Qt.UserRole) or other.text(2)
            return ip_sort_tuple(str(ip1)) < ip_sort_tuple(str(ip2))

        # Col 3: Fabricante (Vendor)
        elif col == 3:
            return self.text(3).lower() < other.text(3).lower()

        # Col 4: Endereço MAC
        elif col == 4:
            return self.text(4).lower() < other.text(4).lower()

        # Col 5: Ping (Numerical Latency in ms, Offline = infinity)
        elif col == 5:
            p1 = self.data(5, Qt.UserRole)
            p2 = other.data(5, Qt.UserRole)
            try:
                val1 = float(p1) if (p1 is not None and float(p1) >= 0) else 999999.0
            except (ValueError, TypeError):
                val1 = 999999.0
            try:
                val2 = float(p2) if (p2 is not None and float(p2) >= 0) else 999999.0
            except (ValueError, TypeError):
                val2 = 999999.0
            return val1 < val2

        # Col 6: Comentários / Serviços
        elif col == 6:
            return self.text(6).lower() < other.text(6).lower()

        return self.text(col).lower() < other.text(col).lower()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP Scan IGT")
        primary = QApplication.primaryScreen()
        if primary:
            geo = primary.availableGeometry()
            w, h = 1280, 760
            x = geo.x() + (geo.width() - w) // 2
            y = geo.y() + (geo.height() - h) // 2
            self.setGeometry(x, y, w, h)
        else:
            self.resize(1280, 760)

        icon_path = get_resource_path("icon.ico") if IS_WINDOWS else get_resource_path("icon.png")
        if not os.path.exists(icon_path):
            icon_path = get_resource_path("icon.png")
        if not os.path.exists(icon_path):
            icon_path = get_resource_path("icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.records: Dict[str, HostRecord] = {}
        self.fav_records: Dict[str, HostRecord] = {}
        self.local_info = get_local_network_info()
        self.is_dark_mode = False  # Default to clean Light Theme like Advanced IP Scanner

        self.scan_worker: Optional[ScanWorker] = None
        self.live_ping_worker = LivePingWorker()
        self.live_ping_worker.sample_ready.connect(self.on_live_ping_sample)
        self.live_ping_worker.start()

        self.table_sweep_timer = QTimer(self)
        self.table_sweep_timer.timeout.connect(self.sweep_table_pings)
        self.table_sweep_timer.start(2500)

        self.init_menu_bar()
        self.init_ui()
        self.load_favorites()
        self.apply_theme()

    def init_menu_bar(self):
        menu_bar = self.menuBar()

        # 1. Arquivo
        menu_file = menu_bar.addMenu("&Arquivo")
        act_csv = QAction("Exportar Resultados para CSV...", self)
        act_csv.setShortcut("Ctrl+S")
        act_csv.triggered.connect(lambda: self.export_results("csv"))
        menu_file.addAction(act_csv)

        act_json = QAction("Exportar Resultados para JSON...", self)
        act_json.triggered.connect(lambda: self.export_results("json"))
        menu_file.addAction(act_json)

        act_txt = QAction("Exportar Relatório em Texto (.txt)...", self)
        act_txt.triggered.connect(lambda: self.export_results("txt"))
        menu_file.addAction(act_txt)

        menu_file.addSeparator()
        act_exit = QAction("Sair", self)
        act_exit.setShortcut("Ctrl+Q")
        act_exit.triggered.connect(self.close)
        menu_file.addAction(act_exit)

        # 2. Ações
        menu_actions = menu_bar.addMenu("&Ações")
        self.act_scan = QAction("Verificar Rede", self)
        self.act_scan.setShortcut("F5")
        self.act_scan.triggered.connect(self.toggle_scan)
        menu_actions.addAction(self.act_scan)

        self.act_stop = QAction("Parar Varredura", self)
        self.act_stop.setShortcut("Esc")
        self.act_stop.triggered.connect(self.toggle_scan)
        menu_actions.addAction(self.act_stop)

        menu_actions.addSeparator()
        act_expand = QAction("Expandir Todos os Serviços [+]", self)
        act_expand.setShortcut("Ctrl+E")
        act_expand.triggered.connect(self.expand_all_results)
        menu_actions.addAction(act_expand)

        act_collapse = QAction("Recolher Todos [-]", self)
        act_collapse.setShortcut("Ctrl+R")
        act_collapse.triggered.connect(self.collapse_all_results)
        menu_actions.addAction(act_collapse)

        menu_actions.addSeparator()
        act_add_fav = QAction("Adicionar Selecionado aos Favoritos", self)
        act_add_fav.setShortcut("Ctrl+D")
        act_add_fav.triggered.connect(self.add_selected_to_favorites)
        menu_actions.addAction(act_add_fav)

        act_scan_fav = QAction("Verificar Somente Favoritos", self)
        act_scan_fav.triggered.connect(self.scan_favorites_only)
        menu_actions.addAction(act_scan_fav)

        menu_actions.addSeparator()
        act_iface = QAction("Selecionar Placa de Rede...", self)
        act_iface.setShortcut("Ctrl+I")
        act_iface.triggered.connect(self.open_interface_dialog)
        menu_actions.addAction(act_iface)

        act_nmap = QAction("Varredura Avançada com Nmap...", self)
        act_nmap.setShortcut("Ctrl+N")
        act_nmap.triggered.connect(self.action_open_nmap)
        menu_actions.addAction(act_nmap)

        # 3. Exibir
        menu_view = menu_bar.addMenu("&Exibir")
        self.act_toggle_bottom = QAction("Painel Inferior de Ping & Detalhes", self)
        self.act_toggle_bottom.setCheckable(True)
        self.act_toggle_bottom.setChecked(True)
        self.act_toggle_bottom.setShortcut("Ctrl+P")
        self.act_toggle_bottom.triggered.connect(self.toggle_bottom_panel)
        menu_view.addAction(self.act_toggle_bottom)

        menu_view.addSeparator()
        act_theme = QAction("Alternar Tema Claro / Escuro", self)
        act_theme.setShortcut("Ctrl+T")
        act_theme.triggered.connect(self.toggle_theme)
        menu_view.addAction(act_theme)

        # 4. Ajuda
        menu_help = menu_bar.addMenu("&Ajuda")
        act_about = QAction("Sobre o IP Scan IGT...", self)
        act_about.triggered.connect(self.show_about_dialog)
        menu_help.addAction(act_about)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- 1. TOP TOOLBAR (Advanced IP Scanner classic style) ---
        top_bar = QFrame()
        top_bar.setObjectName("topBar")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(10, 8, 10, 8)
        top_layout.setSpacing(8)

        # Big "Verificar" green button
        self.btn_start = QPushButton("▶  Verificar")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.setMinimumHeight(38)
        self.btn_start.setMinimumWidth(115)
        self.btn_start.clicked.connect(self.toggle_scan)
        top_layout.addWidget(self.btn_start)

        # "IP" button with network interface picker
        self.btn_subnet = QPushButton("IP ▾")
        self.btn_subnet.setObjectName("btnSubnet")
        self.btn_subnet.setMinimumHeight(38)
        self.btn_subnet.setMinimumWidth(54)
        self.btn_subnet.setToolTip("Preencher faixa IP e selecionar Placa de Rede")
        self.btn_subnet.clicked.connect(self.show_interface_menu)
        top_layout.addWidget(self.btn_subnet)

        # Range inputs
        lbl_from = QLabel("De:")
        lbl_from.setStyleSheet("font-weight: 500;")
        top_layout.addWidget(lbl_from)

        self.txt_start_ip = QLineEdit(self.local_info.get("start_ip", "192.168.1.1"))
        self.txt_start_ip.setFixedWidth(130)
        self.txt_start_ip.setFixedHeight(32)
        top_layout.addWidget(self.txt_start_ip)

        lbl_sep = QLabel("-")
        lbl_sep.setStyleSheet("font-weight: bold; font-size: 14px;")
        top_layout.addWidget(lbl_sep)

        self.txt_end_ip = QLineEdit(self.local_info.get("end_ip", "192.168.1.254"))
        self.txt_end_ip.setFixedWidth(130)
        self.txt_end_ip.setFixedHeight(32)
        top_layout.addWidget(self.txt_end_ip)

        self.combo_mask = QComboBox()
        self.combo_mask.addItems(["/24 (254 IPs)", "/16 (65k IPs)", "/26 (62 IPs)", "/28 (14 IPs)"])
        self.combo_mask.setFixedWidth(125)
        self.combo_mask.setFixedHeight(32)
        self.combo_mask.currentIndexChanged.connect(self.on_mask_changed)
        top_layout.addWidget(self.combo_mask)

        top_layout.addSpacing(6)

        # Quick Expand/Collapse buttons
        btn_expand = QPushButton("+ Expandir")
        btn_expand.setFixedHeight(32)
        btn_expand.setToolTip("Expandir todos os serviços e recursos [+]")
        btn_expand.clicked.connect(self.expand_all_results)
        top_layout.addWidget(btn_expand)

        btn_collapse = QPushButton("- Recolher")
        btn_collapse.setFixedHeight(32)
        btn_collapse.setToolTip("Recolher todos os dispositivos [-]")
        btn_collapse.clicked.connect(self.collapse_all_results)
        top_layout.addWidget(btn_collapse)

        # Search filter
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Filtrar por nome, IP, MAC...")
        self.txt_search.setClearButtonEnabled(True)
        self.txt_search.setFixedHeight(32)
        self.txt_search.textChanged.connect(self.filter_current_tree)
        top_layout.addWidget(self.txt_search)

        # ONVIF auto-discovery toggle
        self.chk_onvif = QCheckBox("🎥 ONVIF")
        self.chk_onvif.setChecked(True)
        self.chk_onvif.setFixedHeight(32)
        self.chk_onvif.setStyleSheet("font-weight: 600; padding: 0 4px;")
        self.chk_onvif.setToolTip("Descobrir câmeras IP e gravadores NVR via protocolo ONVIF (WS-Discovery)")
        top_layout.addWidget(self.chk_onvif)

        # Nmap Scanner tool button
        self.btn_nmap = QPushButton("🔍 Nmap")
        self.btn_nmap.setFixedHeight(32)
        self.btn_nmap.setToolTip("Abrir console de auditoria profunda com Nmap")
        self.btn_nmap.clicked.connect(self.action_open_nmap)
        top_layout.addWidget(self.btn_nmap)

        # Bottom panel toggle button
        self.btn_panel_toggle = QPushButton("▲ Ping & Detalhes")
        self.btn_panel_toggle.setFixedHeight(32)
        self.btn_panel_toggle.setCheckable(True)
        self.btn_panel_toggle.setChecked(True)
        self.btn_panel_toggle.setToolTip("Exibir ou ocultar o painel inferior de osciloscópio e detalhes")
        self.btn_panel_toggle.clicked.connect(self.toggle_bottom_panel)
        top_layout.addWidget(self.btn_panel_toggle)

        # Quick Theme button
        self.btn_theme = QPushButton("Modo Escuro")
        self.btn_theme.setFixedHeight(32)
        self.btn_theme.setToolTip("Alternar Tema Claro / Escuro")
        self.btn_theme.clicked.connect(self.toggle_theme)
        top_layout.addWidget(self.btn_theme)

        main_layout.addWidget(top_bar)

        # --- 2. MAIN CENTRAL SPLITTER (Vertical) ---
        self.main_splitter = QSplitter(Qt.Vertical)
        self.main_splitter.setHandleWidth(5)

        # Upper Area: Main Tabs [Resultados] & [Favoritos] (Takes full horizontal width)
        self.main_tabs = QTabWidget()
        self.main_tabs.setObjectName("mainTabs")

        # Tab 1: Resultados
        tab_results = QWidget()
        results_layout = QVBoxLayout(tab_results)
        results_layout.setContentsMargins(6, 6, 6, 6)

        self.tree = self.create_device_tree()
        self.tree.itemSelectionChanged.connect(lambda: self.on_tree_selection_changed(self.tree))
        self.tree.itemDoubleClicked.connect(self.on_tree_item_double_clicked)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_results_context_menu)
        results_layout.addWidget(self.tree)

        self.main_tabs.addTab(tab_results, "Resultados")

        # Tab 2: Favoritos
        tab_favorites = QWidget()
        fav_layout = QVBoxLayout(tab_favorites)
        fav_layout.setContentsMargins(6, 6, 6, 6)

        # Toolbar on top of Favorites tab
        fav_bar = QHBoxLayout()
        fav_bar.setContentsMargins(0, 0, 0, 4)
        btn_scan_fav = QPushButton("▶  Verificar Favoritos")
        btn_scan_fav.setFixedHeight(28)
        btn_scan_fav.clicked.connect(self.scan_favorites_only)
        btn_del_fav = QPushButton("Remover Selecionado")
        btn_del_fav.setFixedHeight(28)
        btn_del_fav.clicked.connect(self.remove_selected_favorite)
        btn_clear_fav = QPushButton("Limpar Todos")
        btn_clear_fav.setFixedHeight(28)
        btn_clear_fav.clicked.connect(self.clear_all_favorites)
        fav_bar.addWidget(btn_scan_fav)
        fav_bar.addWidget(btn_del_fav)
        fav_bar.addWidget(btn_clear_fav)
        fav_bar.addStretch()
        fav_layout.addLayout(fav_bar)

        self.fav_tree = self.create_device_tree()
        self.fav_tree.itemSelectionChanged.connect(lambda: self.on_tree_selection_changed(self.fav_tree))
        self.fav_tree.itemDoubleClicked.connect(self.on_tree_item_double_clicked)
        self.fav_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.fav_tree.customContextMenuRequested.connect(self.show_fav_context_menu)
        fav_layout.addWidget(self.fav_tree)

        self.main_tabs.addTab(tab_favorites, "Favoritos")
        self.main_splitter.addWidget(self.main_tabs)

        # Lower Area: Retractable Live Ping Oscilloscope & Properties Inspector
        self.bottom_panel = QFrame()
        self.bottom_panel.setObjectName("bottomPanel")
        panel_layout = QVBoxLayout(self.bottom_panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(0)

        # Panel header bar
        panel_header = QFrame()
        panel_header.setObjectName("panelHeader")
        pheader_layout = QHBoxLayout(panel_header)
        pheader_layout.setContentsMargins(10, 4, 10, 4)

        self.lbl_panel_title = QLabel("● Monitor de Ping Dinâmico & Detalhes: [Selecione um dispositivo da lista]")
        self.lbl_panel_title.setStyleSheet("font-weight: bold; font-size: 12px;")
        pheader_layout.addWidget(self.lbl_panel_title)
        pheader_layout.addStretch()

        btn_hide_panel = QPushButton("✕ Fechar")
        btn_hide_panel.setFixedHeight(24)
        btn_hide_panel.clicked.connect(lambda: self.set_bottom_panel_visible(False))
        pheader_layout.addWidget(btn_hide_panel)
        panel_layout.addWidget(panel_header)

        # Panel content: Left = Oscilloscope, Right = Details Table & Actions
        content_box = QHBoxLayout()
        content_box.setContentsMargins(8, 8, 8, 8)
        content_box.setSpacing(10)

        # Left: Live Ping Sparkline
        self.oscilloscope = LivePingOscilloscope()
        self.oscilloscope.setMinimumHeight(110)
        content_box.addWidget(self.oscilloscope, 6)

        # Right: Details Table + Actions
        right_box = QVBoxLayout()
        right_box.setSpacing(6)

        self.details_table = QTableWidget(0, 2)
        self.details_table.setHorizontalHeaderLabels(["Propriedade", "Valor Detalhado"])
        self.details_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.details_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.details_table.verticalHeader().setVisible(False)
        self.details_table.setAlternatingRowColors(True)
        right_box.addWidget(self.details_table)

        # Action buttons
        actions_box = QHBoxLayout()
        actions_box.setSpacing(6)
        btn_open_http = QPushButton("Abrir HTTP")
        btn_open_http.clicked.connect(self.action_open_http)
        btn_open_https = QPushButton("Abrir HTTPS")
        btn_open_https.clicked.connect(self.action_open_https)
        btn_open_smb = QPushButton("Abrir SMB")
        btn_open_smb.clicked.connect(self.action_open_smb)
        btn_rtsp = QPushButton("🎬 Vídeo ao Vivo")
        btn_rtsp.setToolTip("Assistir transmissão de vídeo em tempo real da câmera (RTSP / ONVIF)")
        btn_rtsp.clicked.connect(self.action_open_rtsp)
        btn_nmap_bottom = QPushButton("🔍 Nmap")
        btn_nmap_bottom.clicked.connect(self.action_open_nmap)
        btn_copy_ip = QPushButton("Copiar IP")
        btn_copy_ip.clicked.connect(self.action_copy_current_ip)

        actions_box.addWidget(btn_open_http)
        actions_box.addWidget(btn_open_https)
        actions_box.addWidget(btn_open_smb)
        actions_box.addWidget(btn_rtsp)
        actions_box.addWidget(btn_nmap_bottom)
        actions_box.addWidget(btn_copy_ip)
        right_box.addLayout(actions_box)

        content_box.addLayout(right_box, 4)
        panel_layout.addLayout(content_box)

        self.main_splitter.addWidget(self.bottom_panel)
        self.main_splitter.setSizes([540, 220])

        main_layout.addWidget(self.main_splitter)

        # --- 3. STATUS BAR ---
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.lbl_stats = QLabel(f"Pronto • Interface: {self.local_info.get('interface')} ({self.local_info.get('ip')}) • 0 dispositivos online")
        self.lbl_stats.setStyleSheet("font-weight: 500; margin-left: 10px;")
        self.status_bar.addWidget(self.lbl_stats)

        self.prog_bar = QProgressBar()
        self.prog_bar.setFixedWidth(200)
        self.prog_bar.setFixedHeight(16)
        self.prog_bar.setValue(0)
        self.prog_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.prog_bar)

        self.lbl_threads = QLabel("64 threads ativas")
        self.lbl_threads.setStyleSheet("color: #0969da; font-weight: bold; margin-left: 10px;")
        self.status_bar.addPermanentWidget(self.lbl_threads)

    def create_device_tree(self) -> QTreeWidget:
        tree = QTreeWidget()
        tree.setColumnCount(7)
        tree.setHeaderLabels([
            "Status",
            "Nome",
            "IP",
            "Fabricante",
            "Endereço MAC",
            "Ping",
            "Comentários / Serviços",
        ])
        tree.setAlternatingRowColors(True)

        # Enable clickable column header sorting (Ascending / Descending)
        tree.setSortingEnabled(True)
        tree.header().setSectionsClickable(True)
        tree.header().setSortIndicatorShown(True)
        tree.header().setSortIndicator(2, Qt.AscendingOrder)
        tree.header().sectionClicked.connect(lambda col, t=tree: self.on_tree_header_clicked(t, col))

        tree.header().setSectionResizeMode(0, QHeaderView.Fixed)
        tree.header().resizeSection(0, 55)
        tree.header().setSectionResizeMode(1, QHeaderView.Interactive)
        tree.header().resizeSection(1, 280)
        tree.header().setSectionResizeMode(2, QHeaderView.Interactive)
        tree.header().resizeSection(2, 135)
        tree.header().setSectionResizeMode(3, QHeaderView.Interactive)
        tree.header().resizeSection(3, 190)
        tree.header().setSectionResizeMode(4, QHeaderView.Interactive)
        tree.header().resizeSection(4, 140)
        tree.header().setSectionResizeMode(5, QHeaderView.Interactive)
        tree.header().resizeSection(5, 85)
        tree.header().setSectionResizeMode(6, QHeaderView.Stretch)
        return tree

    def on_tree_header_clicked(self, tree: QTreeWidget, col: int):
        order = tree.header().sortIndicatorOrder()
        order_str = "Crescente ▲" if order == Qt.AscendingOrder else "Decrescente ▼"
        col_names = ["Status", "Nome", "IP", "Fabricante", "Endereço MAC", "Ping", "Comentários"]
        name = col_names[col] if 0 <= col < len(col_names) else f"Coluna {col}"
        self.lbl_stats.setText(f"Classificando por: {name} ({order_str})")

    def apply_theme(self):
        self.setStyleSheet(DARK_STYLESHEET if self.is_dark_mode else LIGHT_STYLESHEET)
        self.btn_theme.setText("Modo Claro" if self.is_dark_mode else "Modo Escuro")
        self.oscilloscope.is_dark = self.is_dark_mode
        self.oscilloscope.update()
        self.lbl_threads.setStyleSheet(
            "color: #38bdf8; font-weight: bold; margin-left: 10px;" if self.is_dark_mode
            else "color: #0969da; font-weight: bold; margin-left: 10px;"
        )

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()

    def toggle_bottom_panel(self):
        vis = not self.bottom_panel.isVisible()
        self.set_bottom_panel_visible(vis)

    def set_bottom_panel_visible(self, visible: bool):
        self.bottom_panel.setVisible(visible)
        self.btn_panel_toggle.setChecked(visible)
        self.act_toggle_bottom.setChecked(visible)
        if visible and sum(self.main_splitter.sizes()) > 0:
            total_h = self.main_splitter.height()
            self.main_splitter.setSizes([int(total_h * 0.72), int(total_h * 0.28)])

    def expand_all_results(self):
        current_tree = self.get_active_tree()
        current_tree.expandAll()

    def collapse_all_results(self):
        current_tree = self.get_active_tree()
        current_tree.collapseAll()

    def get_active_tree(self) -> QTreeWidget:
        if self.main_tabs.currentIndex() == 1:
            return self.fav_tree
        return self.tree

    def filter_current_tree(self, text: str):
        query = text.strip().lower()
        tree = self.get_active_tree()
        for i in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(i)
            match = False
            for col in range(tree.columnCount()):
                if query in item.text(col).lower():
                    match = True
                    break
            item.setHidden(not match)

    def show_interface_menu(self):
        interfaces = get_all_network_interfaces()
        if not interfaces:
            QMessageBox.warning(self, "Aviso", "Nenhuma placa de rede ativa com endereço IPv4 foi encontrada.")
            return

        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 4px;
            }
            QMenu::item {
                padding: 6px 16px;
                font-size: 12px;
            }
            QMenu::item:selected {
                background-color: #e0f2fe;
                color: #0369a1;
            }
        """)

        hdr = menu.addAction("── Placas de Rede Disponíveis ──")
        hdr.setEnabled(False)

        current_name = self.local_info.get("name") or self.local_info.get("interface", "")

        for iface in interfaces:
            is_active = iface["name"] == current_name
            prefix_mark = "✔ " if is_active else "    "
            speed_info = f" • {iface['speed']}" if iface.get("speed") else ""
            default_tag = " [Padrão]" if iface.get("is_default") else ""
            label = f"{prefix_mark}{iface['icon']} {iface['name']}{default_tag} ({iface['type']}): {iface['ip']}/{iface['cidr']}  [{iface['start_ip']} - {iface['end_ip']}]{speed_info}"
            act = menu.addAction(label)
            act.triggered.connect(lambda checked, info=iface: self.select_network_interface(info))

        menu.addSeparator()
        act_dialog = menu.addAction("⚙️  Gerenciar e Ver Detalhes das Placas...")
        act_dialog.triggered.connect(self.open_interface_dialog)

        # Popup menu right below the "IP" button
        btn_pos = self.btn_subnet.mapToGlobal(QPoint(0, self.btn_subnet.height() + 2))
        menu.exec_(btn_pos)

    def select_network_interface(self, iface_info: dict):
        self.local_info = iface_info
        start_ip = iface_info.get("start_ip", "")
        end_ip = iface_info.get("end_ip", "")
        cidr = iface_info.get("cidr", "24")

        if start_ip:
            self.txt_start_ip.setText(start_ip)
        if end_ip:
            self.txt_end_ip.setText(end_ip)

        prefix_map = {"24": 0, "16": 1, "26": 2, "28": 3}
        if str(cidr) in prefix_map:
            self.combo_mask.blockSignals(True)
            self.combo_mask.setCurrentIndex(prefix_map[str(cidr)])
            self.combo_mask.blockSignals(False)

        iface_name = iface_info.get("name", "eth0")
        ip_addr = iface_info.get("ip", "")
        self.lbl_stats.setText(f"Placa selecionada: {iface_info.get('icon', '🖧')} {iface_name} ({ip_addr}/{cidr}) • Faixa: {start_ip} - {end_ip}")

    def open_interface_dialog(self):
        cur_name = self.local_info.get("name") or self.local_info.get("interface", "")
        dlg = NetworkInterfaceDialog(self, current_interface=cur_name)
        dlg.interface_selected.connect(self.select_network_interface)
        dlg.exec_()

    def apply_class_c(self):
        """Fallback helper if called programmatically."""
        self.select_network_interface(self.local_info)

    def on_mask_changed(self):
        idx = self.combo_mask.currentIndex()
        prefix = [24, 16, 26, 28][idx]
        try:
            start_ip = self.txt_start_ip.text().strip()
            net = ipaddress.IPv4Network(f"{start_ip}/{prefix}", strict=False)
            hosts = list(net.hosts())
            if hosts:
                self.txt_start_ip.setText(str(hosts[0]))
                self.txt_end_ip.setText(str(hosts[-1]))
        except Exception:
            pass

    def toggle_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.set_scan_running_state(False)
            self.lbl_stats.setText("Parando varredura...")
            return

        start_ip = self.txt_start_ip.text().strip()
        end_ip = self.txt_end_ip.text().strip()

        try:
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            if start_int > end_int:
                start_int, end_int = end_int, start_int
            if (end_int - start_int) > 65536:
                QMessageBox.warning(self, "Faixa Muito Grande", "A faixa excede 65.536 endereços IP. Por favor, especifique uma sub-rede /16 ou menor.")
                return
            ip_list = [str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)]
        except Exception as e:
            QMessageBox.warning(self, "Faixa Inválida", f"Endereço IP inválido especificado: {e}")
            return

        self.records.clear()
        self.tree.clear()
        self.details_table.setRowCount(0)
        self.oscilloscope.clear()
        self.live_ping_worker.set_target("")
        self.lbl_panel_title.setText("● Monitor de Ping Dinâmico & Detalhes: [Selecione um dispositivo da lista]")
        self.main_tabs.setCurrentIndex(0)  # Switch to Resultados

        self.set_scan_running_state(True, len(ip_list))

        self.scan_worker = ScanWorker(ip_list, self.local_info, enable_onvif=self.chk_onvif.isChecked(), max_workers=64)
        self.scan_worker.host_found.connect(self.on_host_found)
        self.scan_worker.progress_updated.connect(self.on_scan_progress)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def scan_favorites_only(self):
        if not self.fav_records:
            QMessageBox.information(self, "Favoritos Vazios", "Nenhum dispositivo salvo nos Favoritos para verificar.")
            return

        ip_list = list(self.fav_records.keys())
        self.main_tabs.setCurrentIndex(1)  # Switch to Favoritos
        self.fav_tree.clear()

        self.set_scan_running_state(True, len(ip_list))

        self.scan_worker = ScanWorker(ip_list, self.local_info, enable_onvif=self.chk_onvif.isChecked(), max_workers=32)
        self.scan_worker.host_found.connect(lambda rec: self.on_fav_host_found(rec))
        self.scan_worker.progress_updated.connect(self.on_scan_progress)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def set_scan_running_state(self, running: bool, total: int = 0):
        if running:
            self.btn_start.setText("⏹  Parar")
            self.btn_start.setObjectName("btnStop")
            self.btn_start.setStyle(self.btn_start.style())
            self.act_scan.setEnabled(False)
            self.act_stop.setEnabled(True)
            self.prog_bar.setMaximum(total)
            self.prog_bar.setValue(0)
            self.prog_bar.setVisible(True)
        else:
            self.btn_start.setText("▶  Verificar")
            self.btn_start.setObjectName("btnStart")
            self.btn_start.setStyle(self.btn_start.style())
            self.act_scan.setEnabled(True)
            self.act_stop.setEnabled(False)
            self.prog_bar.setVisible(False)

    @pyqtSlot(int, int, str)
    def on_scan_progress(self, current: int, total: int, current_ip: str):
        self.prog_bar.setValue(current)
        self.lbl_stats.setText(f"Verificando: {current_ip} ({current}/{total})...")

    @pyqtSlot(object)
    def on_host_found(self, rec: HostRecord):
        self.records[rec.ip] = rec
        self.add_or_update_tree_node(self.tree, rec)
        self.update_status_stats()

    def on_fav_host_found(self, rec: HostRecord):
        self.fav_records[rec.ip] = rec
        self.add_or_update_tree_node(self.fav_tree, rec)
        self.update_status_stats()

    @pyqtSlot(int, float)
    def on_scan_finished(self, found_count: int, elapsed_sec: float):
        self.set_scan_running_state(False)
        self.lbl_stats.setText(f"Concluído em {elapsed_sec:.1f}s • {found_count} dispositivo(s) online encontrado(s)")
        col = self.tree.sortColumn()
        order = self.tree.header().sortIndicatorOrder()
        self.tree.sortItems(col if col >= 0 else 2, order)
        self.update_status_stats()

    def add_or_update_tree_node(self, target_tree: QTreeWidget, rec: HostRecord):
        parent_item = None
        for i in range(target_tree.topLevelItemCount()):
            it = target_tree.topLevelItem(i)
            if it.data(2, Qt.UserRole) == rec.ip:
                parent_item = it
                break

        if not parent_item:
            parent_item = DeviceTreeWidgetItem(target_tree)

        parent_item.setData(0, Qt.UserRole, 1 if rec.alive else 0)
        parent_item.setData(2, Qt.UserRole, rec.ip)
        parent_item.setData(5, Qt.UserRole, rec.rtt_ms)

        # Col 0: Status Orb (Green circle for online, gray for offline)
        parent_item.setText(0, "●" if rec.alive else "○")
        parent_item.setTextAlignment(0, Qt.AlignCenter)
        parent_item.setForeground(0, QColor("#16a34a") if rec.alive else QColor("#94a3b8"))
        font_status = QFont("Noto Sans", 14, QFont.Bold)
        parent_item.setFont(0, font_status)

        # Col 1: Nome (Hostname or device type)
        display_name = rec.hostname or f"Host [{rec.ip}]"
        parent_item.setText(1, display_name)

        # Col 2: IP
        parent_item.setText(2, rec.ip)

        # Col 3: Fabricante
        parent_item.setText(3, rec.vendor or "Desconhecido")

        # Col 4: MAC
        parent_item.setText(4, rec.mac or "N/D")

        # Col 5: Ping
        parent_item.setText(5, rec.format_ping())
        if rec.rtt_ms >= 0:
            if rec.rtt_ms < 2.0:
                parent_item.setForeground(5, QColor("#107c41") if not self.is_dark_mode else QColor("#10b981"))
            elif rec.rtt_ms < 20.0:
                parent_item.setForeground(5, QColor("#0969da") if not self.is_dark_mode else QColor("#38bdf8"))
            else:
                parent_item.setForeground(5, QColor("#b45309") if not self.is_dark_mode else QColor("#f59e0b"))

        # Col 6: Comentários / Serviços
        comment_parts = []
        if rec.device_type and rec.device_type != "🖧 Host Online":
            comment_parts.append(rec.device_type)
        if rec.http_info:
            comment_parts.append(rec.http_info)
        elif rec.ssl_info:
            comment_parts.append(f"SSL: {rec.ssl_info}")
        elif rec.ssh_banner:
            comment_parts.append(rec.ssh_banner)
        if rec.open_ports:
            comment_parts.append(f"Portas: {rec.format_ports()}")

        parent_item.setText(6, " • ".join(comment_parts) if comment_parts else "Nenhum serviço identificado")

        # Sub-items [ + ] for individual services (HTTP, HTTPS, SMB, etc.)
        parent_item.takeChildren()
        link_color = QColor("#0969da") if not self.is_dark_mode else QColor("#38bdf8")
        text_color = QColor("#475569") if not self.is_dark_mode else QColor("#cbd5e1")

        for res in rec.resources:
            child = QTreeWidgetItem(parent_item)
            child.setText(1, f"    {res.icon}  {res.title}")
            child.setText(2, res.url or "")
            child.setText(6, res.detail)
            child.setData(2, Qt.UserRole, rec.ip)
            child.setData(1, Qt.UserRole, res.url)
            child.setForeground(1, link_color if res.url else text_color)
            if res.url:
                child.setForeground(2, link_color)

        # Keep collapsed by default for clean and uncluttered UI/UX
        parent_item.setExpanded(False)

    def sort_tree_by_ip(self, target_tree: QTreeWidget):
        col = target_tree.sortColumn()
        order = target_tree.header().sortIndicatorOrder()
        target_tree.sortItems(col if col >= 0 else 2, order)

    def update_status_stats(self):
        tree = self.get_active_tree()
        online_count = tree.topLevelItemCount()
        records_pool = self.records if self.main_tabs.currentIndex() == 0 else self.fav_records

        services_count = sum(1 for r in records_pool.values() if r.open_ports)
        rtts = [r.rtt_ms for r in records_pool.values() if r.rtt_ms >= 0]
        avg_rtt = f"{sum(rtts)/len(rtts):.2f} ms" if rtts else "--"

        self.lbl_stats.setText(
            f"Resultados: {online_count} dispositivo(s) online  |  "
            f"{services_count} com serviços  |  "
            f"Latência média: {avg_rtt}"
        )

    def on_tree_selection_changed(self, tree: QTreeWidget):
        items = tree.selectedItems()
        if not items:
            return

        item = items[0]
        ip = item.data(2, Qt.UserRole)
        if not ip:
            return

        records_pool = self.records if tree == self.tree else self.fav_records
        if ip not in records_pool:
            return

        rec = records_pool[ip]
        self.lbl_panel_title.setText(f"● Monitor de Ping Dinâmico & Detalhes: {rec.ip} — {rec.hostname or 'Dispositivo'}")
        self.oscilloscope.clear(ip)
        self.live_ping_worker.set_target(ip)
        self.populate_details_table(rec)

    def populate_details_table(self, rec: HostRecord):
        props = [
            ("Endereço IP", rec.ip),
            ("Nome / Hostname", rec.hostname or "Não configurado"),
            ("Tipo / Sistema", f"{rec.device_type} • {rec.os_family}"),
            ("Fabricante (OUI)", rec.vendor or "Não identificado"),
            ("Endereço MAC", rec.mac or "Não disponível"),
            ("Latência (Ping)", f"{rec.format_ping()} (Método: {rec.ping_method})"),
            ("TTL de Rede", f"{rec.ttl} ({'Rede Local Direta' if rec.ttl in [64, 128, 255] else 'Saltos detectados'})" if rec.ttl > 0 else "N/D"),
            ("Portas TCP Abertas", rec.format_ports() or "Nenhuma porta padrão aberta"),
            ("HTTP / Servidor Web", rec.http_info or "Nenhum"),
            ("Certificado SSL / HTTPS", f"CN={rec.ssl_info}" if rec.ssl_info else "Nenhum"),
            ("Banner SSH (Porta 22)", rec.ssh_banner or "Fechada"),
            ("NetBIOS / Grupo SMB", rec.netbios_domain or "N/D"),
        ]

        if rec.onvif_url or rec.onvif_model:
            props.append(("ONVIF Câmera / NVR", f"{rec.onvif_model} ({rec.onvif_url})"))
        if rec.rtsp_url or 554 in rec.open_ports:
            props.append(("Stream RTSP de Vídeo", rec.rtsp_url or f"rtsp://{rec.ip}:554/"))
        if rec.nmap_services:
            svc_str = "; ".join(f"{p}: {s}" for p, s in rec.nmap_services.items())
            props.append(("Serviços Auditados (Nmap)", svc_str))

        self.details_table.setRowCount(len(props))
        for row, (k, v) in enumerate(props):
            item_k = QTableWidgetItem(k)
            item_k.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            item_v = QTableWidgetItem(v)
            item_v.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            self.details_table.setItem(row, 0, item_k)
            self.details_table.setItem(row, 1, item_v)

    @pyqtSlot(str, float, int, str)
    def on_live_ping_sample(self, ip: str, rtt: float, ttl: int, method: str):
        if self.oscilloscope.current_ip == ip:
            self.oscilloscope.add_sample(rtt, ttl, method)
            records_pool = self.records if ip in self.records else self.fav_records
            if ip in records_pool and rtt >= 0:
                records_pool[ip].rtt_ms = rtt
                records_pool[ip].alive = True
                if ttl > 0:
                    records_pool[ip].ttl = ttl

                # Update ping cell in current active tree
                tree = self.get_active_tree()
                for i in range(tree.topLevelItemCount()):
                    it = tree.topLevelItem(i)
                    if it.data(2, Qt.UserRole) == ip:
                        it.setText(5, f"{rtt:.2f} ms")
                        it.setData(5, Qt.UserRole, rtt)
                        ping_col = QColor("#107c41") if not self.is_dark_mode else QColor("#10b981")
                        it.setForeground(5, ping_col if rtt < 2.0 else (QColor("#0969da") if not self.is_dark_mode else QColor("#38bdf8")))
                        break

    def sweep_table_pings(self):
        """Lightweight non-blocking background ping sweep to keep table latencies fresh."""
        if self.scan_worker and self.scan_worker.isRunning():
            return
        if hasattr(self, "_sweep_worker") and self._sweep_worker and self._sweep_worker.isRunning():
            return

        selected_ip = self.oscilloscope.current_ip
        tree = self.get_active_tree()
        records_pool = self.records if tree == self.tree else self.fav_records
        online_ips = [ip for ip in records_pool.keys() if ip != selected_ip][:10]
        if not online_ips:
            return

        self._sweep_worker = PingSweepWorker(online_ips)
        self._sweep_worker.batch_finished.connect(self.on_sweep_results)
        self._sweep_worker.start()

    def on_sweep_results(self, results: list):
        tree = self.get_active_tree()
        records_pool = self.records if tree == self.tree else self.fav_records
        for ip, rtt in results:
            if rtt >= 0 and ip in records_pool:
                records_pool[ip].rtt_ms = rtt
                for i in range(tree.topLevelItemCount()):
                    it = tree.topLevelItem(i)
                    if it.data(2, Qt.UserRole) == ip:
                        it.setText(5, f"{rtt:.2f} ms")
                        it.setData(5, Qt.UserRole, rtt)
                        break

    def launch_rtsp_stream(self, rtsp_url: str, ip: str = ""):
        target_ip = ip
        if not target_ip:
            m = re.search(r"rtsp://([0-9\.]+)", rtsp_url)
            if m:
                target_ip = m.group(1)

        real_url = rtsp_url
        # If URL is generic (ends with :554/ or missing path), resolve exact tokenized URI from camera ONVIF
        if target_ip and (not real_url or real_url.endswith(":554/") or real_url.endswith(":554")):
            try:
                from onvif_engine import get_onvif_stream_uri
                resolved = get_onvif_stream_uri(target_ip)
                if resolved:
                    real_url = resolved
                    rec = self.records.get(target_ip) or self.fav_records.get(target_ip)
                    if rec:
                        rec.rtsp_url = resolved
            except Exception:
                pass

        from onvif_engine import launch_video_player
        title = f"Câmera IP {target_ip or ''} — IP Scan IGT".strip()
        launched = launch_video_player(real_url, title=title)
        if not launched:
            QMessageBox.warning(
                self,
                "Player de Vídeo",
                f"Nem FFplay nem VLC foram encontrados no sistema para reproduzir o fluxo RTSP.\n\nInstale o VLC Media Player ou FFmpeg para reprodução direta.\n\nURL do Fluxo:\n{real_url}",
            )

    def on_tree_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        url = item.data(1, Qt.UserRole)
        ip = item.data(2, Qt.UserRole) or ""
        if url:
            if url.startswith("rtsp://"):
                self.launch_rtsp_stream(url, ip=ip)
            else:
                QDesktopServices.openUrl(QUrl(url))
            return
        records_pool = self.records if ip in self.records else self.fav_records
        if ip and ip in records_pool:
            rec = records_pool[ip]
            if rec.rtsp_url or 554 in rec.open_ports:
                self.launch_rtsp_stream(rec.rtsp_url or f"rtsp://{ip}:554/", ip=ip)
            elif 443 in rec.open_ports:
                QDesktopServices.openUrl(QUrl(f"https://{ip}/"))
            elif 80 in rec.open_ports:
                QDesktopServices.openUrl(QUrl(f"http://{ip}/"))
            elif 8006 in rec.open_ports:
                QDesktopServices.openUrl(QUrl(f"https://{ip}:8006/"))
            elif 445 in rec.open_ports:
                open_smb(ip)

    def show_results_context_menu(self, pos: QPoint):
        item = self.tree.itemAt(pos)
        if not item:
            return
        ip = item.data(2, Qt.UserRole)
        if not ip or ip not in self.records:
            return
        rec = self.records[ip]

        menu = QMenu(self)
        a_add_fav = menu.addAction("★ Adicionar aos Favoritos")
        menu.addSeparator()

        a_rtsp = None
        if rec.rtsp_url or 554 in rec.open_ports:
            a_rtsp = menu.addAction("🎬 Assistir Transmissão ao Vivo (RTSP)")

        a_onvif = None
        if rec.onvif_url:
            a_onvif = menu.addAction("🎥 Abrir Painel ONVIF no Navegador")

        a_nmap = menu.addAction("🔍 Escanear com Nmap (-sV)...")
        menu.addSeparator()

        a_open_http = menu.addAction("Abrir no Navegador (HTTP)")
        a_open_https = menu.addAction("Abrir no Navegador Seguro (HTTPS)")
        a_open_smb = menu.addAction("Abrir Compartilhamento de Rede (SMB)")
        menu.addSeparator()

        a_copy_ip = menu.addAction("Copiar Endereço IP")
        a_copy_mac = menu.addAction("Copiar Endereço MAC")
        a_copy_all = menu.addAction("Copiar Relatório Completo")
        menu.addSeparator()

        a_term_ping = menu.addAction("Ping Contínuo no Terminal")

        action = menu.exec_(self.tree.viewport().mapToGlobal(pos))
        if action == a_add_fav:
            self.add_record_to_favorites(rec)
        elif a_rtsp and action == a_rtsp:
            self.launch_rtsp_stream(rec.rtsp_url or f"rtsp://{rec.ip}:554/", ip=rec.ip)
        elif a_onvif and action == a_onvif:
            QDesktopServices.openUrl(QUrl(rec.onvif_url))
        elif action == a_nmap:
            self.open_nmap_dialog(rec.ip, rec.hostname)
        elif action == a_open_http:
            QDesktopServices.openUrl(QUrl(f"http://{rec.ip}/"))
        elif action == a_open_https:
            QDesktopServices.openUrl(QUrl(f"https://{rec.ip}/"))
        elif action == a_open_smb:
            open_smb(rec.ip)
        elif action == a_copy_ip:
            QApplication.clipboard().setText(rec.ip)
        elif action == a_copy_mac:
            QApplication.clipboard().setText(rec.mac)
        elif action == a_copy_all:
            report = f"IP: {rec.ip}\nNome: {rec.hostname}\nFabricante: {rec.vendor}\nMAC: {rec.mac}\nPing: {rec.format_ping()}\nTipo: {rec.device_type}\nBanners: {rec.http_info}\nPortas: {rec.format_ports()}\n"
            QApplication.clipboard().setText(report)
        elif action == a_term_ping:
            open_terminal_ping(rec.ip)

    def show_fav_context_menu(self, pos: QPoint):
        item = self.fav_tree.itemAt(pos)
        if not item:
            return
        ip = item.data(2, Qt.UserRole)
        if not ip or ip not in self.fav_records:
            return
        rec = self.fav_records[ip]

        menu = QMenu(self)
        a_remove = menu.addAction("Remover dos Favoritos")
        menu.addSeparator()
        a_rtsp = None
        if rec.rtsp_url or 554 in rec.open_ports:
            a_rtsp = menu.addAction("🎬 Assistir Transmissão ao Vivo (RTSP)")
        a_nmap = menu.addAction("🔍 Escanear com Nmap (-sV)...")
        menu.addSeparator()
        a_open_http = menu.addAction("Abrir HTTP")
        a_open_smb = menu.addAction("Abrir SMB")
        a_term_ping = menu.addAction("Ping no Terminal")
        a_copy_ip = menu.addAction("Copiar IP")

        action = menu.exec_(self.fav_tree.viewport().mapToGlobal(pos))
        if action == a_remove:
            self.remove_favorite_ip(rec.ip)
        elif a_rtsp and action == a_rtsp:
            self.launch_rtsp_stream(rec.rtsp_url or f"rtsp://{rec.ip}:554/", ip=rec.ip)
        elif action == a_nmap:
            self.open_nmap_dialog(rec.ip, rec.hostname)
        elif action == a_open_http:
            QDesktopServices.openUrl(QUrl(f"http://{rec.ip}/"))
        elif action == a_open_smb:
            open_smb(rec.ip)
        elif action == a_term_ping:
            open_terminal_ping(rec.ip)
        elif action == a_copy_ip:
            QApplication.clipboard().setText(rec.ip)

    def add_selected_to_favorites(self):
        items = self.tree.selectedItems()
        if not items:
            QMessageBox.information(self, "Aviso", "Selecione um dispositivo da lista de Resultados primeiro.")
            return
        ip = items[0].data(2, Qt.UserRole)
        if ip and ip in self.records:
            self.add_record_to_favorites(self.records[ip])

    def add_record_to_favorites(self, rec: HostRecord):
        if not rec or not rec.ip:
            return
        self.fav_records[rec.ip] = rec
        self.add_or_update_tree_node(self.fav_tree, rec)
        self.save_favorites_to_disk()
        self.lbl_stats.setText(f"Dispositivo {rec.ip} ({rec.hostname}) adicionado aos Favoritos.")

    def remove_selected_favorite(self):
        items = self.fav_tree.selectedItems()
        if not items:
            return
        ip = items[0].data(2, Qt.UserRole)
        if ip:
            self.remove_favorite_ip(ip)

    def remove_favorite_ip(self, ip: str):
        if ip in self.fav_records:
            del self.fav_records[ip]
            for i in range(self.fav_tree.topLevelItemCount()):
                it = self.fav_tree.topLevelItem(i)
                if it.data(2, Qt.UserRole) == ip:
                    self.fav_tree.takeTopLevelItem(i)
                    break
            self.save_favorites_to_disk()
            self.lbl_stats.setText(f"Dispositivo {ip} removido dos Favoritos.")

    def clear_all_favorites(self):
        if not self.fav_records:
            return
        res = QMessageBox.question(self, "Limpar Favoritos", "Deseja remover todos os dispositivos salvos dos Favoritos?", QMessageBox.Yes | QMessageBox.No)
        if res == QMessageBox.Yes:
            self.fav_records.clear()
            self.fav_tree.clear()
            self.save_favorites_to_disk()

    def action_open_http(self):
        ip = self.oscilloscope.current_ip
        if ip:
            QDesktopServices.openUrl(QUrl(f"http://{ip}/"))

    def action_open_https(self):
        ip = self.oscilloscope.current_ip
        if ip:
            QDesktopServices.openUrl(QUrl(f"https://{ip}/"))

    def action_open_smb(self):
        ip = self.oscilloscope.current_ip
        if ip:
            open_smb(ip)

    def action_open_rtsp(self):
        ip = self.oscilloscope.current_ip
        if not ip:
            return
        rec = self.records.get(ip) or self.fav_records.get(ip)
        rtsp = rec.rtsp_url if rec and rec.rtsp_url else f"rtsp://{ip}:554/"
        self.launch_rtsp_stream(rtsp, ip=ip)

    def action_open_nmap(self):
        ip = self.oscilloscope.current_ip
        rec = self.records.get(ip) or self.fav_records.get(ip)
        hostname = rec.hostname if rec else ""
        target = ip or self.txt_start_ip.text().strip()
        self.open_nmap_dialog(target_ip=target, hostname=hostname)

    def open_nmap_dialog(self, target_ip: str = "", hostname: str = ""):
        dlg = NmapDialog(self, target=target_ip, hostname=hostname)
        dlg.ports_applied.connect(self.on_nmap_ports_applied)
        dlg.exec_()

    @pyqtSlot(str, list, dict)
    def on_nmap_ports_applied(self, ip: str, open_ports: list, services: dict):
        records_pool = self.records if ip in self.records else self.fav_records
        if ip in records_pool:
            rec = records_pool[ip]
            for p in open_ports:
                if p not in rec.open_ports:
                    rec.open_ports.append(p)
            rec.open_ports.sort()
            rec.nmap_services.update(services)
            rec.device_type, rec.os_family = classify_device(rec)
            rec.resources = build_resources_for_host(rec)

            tree = self.get_active_tree()
            self.add_or_update_tree_node(tree, rec)
            if self.oscilloscope.current_ip == ip:
                self.populate_details_table(rec)
            self.update_status_stats()
            self.lbl_stats.setText(f"Portas e serviços atualizados via Nmap para o host {ip}.")

    def action_copy_current_ip(self):
        ip = self.oscilloscope.current_ip
        if ip:
            QApplication.clipboard().setText(ip)
            self.lbl_stats.setText(f"Endereço IP {ip} copiado para a área de transferência.")

    def export_results(self, fmt: str = "csv"):
        records_to_export = self.records if self.main_tabs.currentIndex() == 0 else self.fav_records
        if not records_to_export:
            QMessageBox.information(self, "Exportar", "Nenhum resultado para exportar.")
            return

        filter_str = "Arquivo CSV (*.csv)" if fmt == "csv" else ("Arquivo JSON (*.json)" if fmt == "json" else "Arquivo TXT (*.txt)")
        default_name = f"relatorio_rede.{fmt}"
        path, _ = QFileDialog.getSaveFileName(self, "Exportar Resultados", os.path.expanduser(f"~/{default_name}"), filter_str)
        if not path:
            return

        try:
            if fmt == "json":
                data = [dict(r.__dict__) for r in records_to_export.values()]
                for d in data:
                    d.pop("resources", None)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            elif fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    f.write("IP SCAN IGT — RELATÓRIO DE REDE\n" + "=" * 55 + "\n\n")
                    for r in records_to_export.values():
                        f.write(f"IP: {r.ip:16} | Host: {r.hostname:25} | MAC: {r.mac:18} | Fabricante: {r.vendor:25} | Ping: {r.format_ping()}\n")
            else:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Status", "Nome", "IP", "Fabricante", "Endereço MAC", "Ping", "Tipo / SO", "Portas Abertas"])
                    for r in records_to_export.values():
                        writer.writerow(["Online" if r.alive else "Offline", r.hostname, r.ip, r.vendor, r.mac, r.format_ping(), r.device_type, r.format_ports()])

            QMessageBox.information(self, "Sucesso", f"Resultados salvos com sucesso em:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao Exportar", str(e))

    def load_favorites(self):
        os.makedirs(os.path.dirname(FAVORITES_FILE), exist_ok=True)
        if os.path.exists(FAVORITES_FILE):
            try:
                with open(FAVORITES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        ip = item.get("ip", "").strip()
                        if not ip:
                            continue
                        rec = HostRecord(
                            ip=ip,
                            hostname=item.get("hostname", ""),
                            vendor=item.get("vendor", ""),
                            mac=item.get("mac", ""),
                            alive=item.get("alive", True),
                            rtt_ms=item.get("rtt_ms", 0.0),
                            device_type=item.get("device_type", ""),
                        )
                        self.fav_records[rec.ip] = rec
                        self.add_or_update_tree_node(self.fav_tree, rec)
            except Exception:
                pass

    def save_favorites_to_disk(self):
        try:
            data = []
            for r in self.fav_records.values():
                if not r.ip:
                    continue
                data.append({
                    "ip": r.ip,
                    "hostname": r.hostname,
                    "vendor": r.vendor,
                    "mac": r.mac,
                    "alive": r.alive,
                    "rtt_ms": r.rtt_ms,
                    "device_type": r.device_type,
                })
            with open(FAVORITES_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def show_about_dialog(self):
        QMessageBox.about(
            self,
            "Sobre o IP Scan IGT",
            "<b>IP Scan IGT — Edição Nativa Linux</b><br><br>"
            "Scanner profissional de IP e dispositivos de rede de alta velocidade construído especificamente para Linux.<br><br>"
            "<b>Principais Características:</b><br>"
            "• Interface inspirada no clássico <i>Advanced IP Scanner</i> com abas [Resultados] e [Favoritos]<br>"
            "• Descoberta de nomes via NetBIOS, mDNS, LLMNR, SMB2 NTLMSSP, HTTP e SSL/TLS<br>"
            "• <b>Suporte ONVIF & RTSP:</b> Detecção automática de câmeras de segurança e gravadores NVR com reprodução de vídeo via VLC/ffplay<br>"
            "• <b>Integração Nmap:</b> Auditoria profunda de portas e detecção de versões de serviços sem necessidade de sudo<br>"
            "• <b>Classificação Dinâmica:</b> Ordenação em 1 clique (Crescente ▲ / Decrescente ▼) por IP numérico, Nome, Ping, MAC e Fabricante<br>"
            "• <b>Seletor de Placas de Rede:</b> Detecção e preenchimento automático para Ethernet, Wi-Fi, VPN e Bridges<br>"
            "• Expansão inline [+] para serviços HTTP, HTTPS, SSH, SMB e RTSP<br>"
            "• Osciloscópio de Ping Instantâneo em tempo real com gráfico dinâmico<br>"
            "• Motor multi-thread rápido e nativo com suporte a sub-milissegundos.",
        )

    def closeEvent(self, event):
        self.table_sweep_timer.stop()
        if hasattr(self, "_sweep_worker") and self._sweep_worker and self._sweep_worker.isRunning():
            self._sweep_worker.wait(500)
        self.live_ping_worker.stop()
        self.live_ping_worker.wait(1000)
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait(1000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("IP Scan IGT")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
