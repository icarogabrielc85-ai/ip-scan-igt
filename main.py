#!/usr/bin/env python3
import concurrent.futures
import csv
import io
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
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
    from PyQt5 import QtCore, QtGui, QtWidgets
except ImportError as e:
    print("=" * 65)
    print("             IP SCAN IGT - VERIFICANDO DEPENDÊNCIAS")
    print("=" * 65)
    print("[*] A biblioteca gráfica PyQt5 não foi encontrada no seu Python.")
    print("[*] Instalando PyQt5 automaticamente via pip... Por favor, aguarde...")
    print("")
    try:
        pip_cmd = [sys.executable, "-m", "pip", "install", "PyQt5>=5.15.9"]
        if not IS_WINDOWS:
            pip_cmd.extend(["--break-system-packages", "--user"])
        subprocess.check_call(pip_cmd)
        from PyQt5 import QtCore, QtGui, QtWidgets
        print("\n[OK] PyQt5 foi instalado com sucesso! Iniciando aplicativo...\n")
    except Exception as err:
        msg = (
            f"O IP Scan IGT precisa do pacote PyQt5 para abrir a interface gráfica.\n\n"
            f"A instalação automática falhou com o erro:\n{err}\n\n"
            f"Solução:\n"
            f"Abra o Prompt de Comando (CMD) e execute manualmente:\n"
            f"pip install PyQt5>=5.15.9"
        )
        print(f"\n[ERRO FATAL]\n{msg}\n")
        if IS_WINDOWS:
            try:
                import ctypes
                ctypes.windll.user32.MessageBoxW(0, msg, "IP Scan IGT - Dependência Ausente", 0x10)
            except Exception:
                pass
            try:
                input("\nPressione ENTER para fechar esta janela...")
            except Exception:
                pass
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


def open_rdp(ip: str) -> bool:
    if not ip:
        return False
    if IS_WINDOWS:
        try:
            subprocess.Popen(["mstsc", f"/v:{ip}"])
            return True
        except Exception:
            return False
    else:
        clients = [
            ("remmina", ["remmina", "-c", f"rdp://{ip}"]),
            ("xfreerdp", ["xfreerdp", f"/v:{ip}", "/cert-ignore", "+clipboard"]),
            ("krdc", ["krdc", f"rdp://{ip}"]),
            ("rdesktop", ["rdesktop", "-u", "", ip]),
        ]
        for name, cmd in clients:
            if shutil.which(name):
                try:
                    subprocess.Popen(cmd)
                    return True
                except Exception:
                    pass
        return False


from ssh_dialog import SshConnectDialog, open_terminal_ssh
from video_config_dialog import VideoConfigDialog, get_video_config

from PyQt5.QtCore import QObject, QPoint, QProcess, QSize, Qt, QThread, QTimer, QUrl, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor, QDesktopServices, QFont, QIcon, QPixmap
from PyQt5.QtWidgets import (
    QAction,
    QActionGroup,
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
    QProgressDialog,
    QPushButton,
    QSplitter,
    QStatusBar,
    QSystemTrayIcon,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from i18n import SUPPORTED_LANGUAGES, get_current_language, set_current_language, tr

from oui_db import OUI_DB
from scanner_engine import (
    HostRecord,
    ResourceItem,
    build_resources_for_host,
    classify_device,
    correlate_host_vulnerabilities,
    get_all_network_interfaces,
    get_local_network_info,
    probe_ping,
    read_linux_arp_table,
    robust_urlopen,
    scan_single_ip,
    send_wake_on_lan,
)
from onvif_engine import discover_onvif_devices, probe_rtsp
from nmap_engine import is_nmap_available, get_nmap_path
from nmap_dialog import NmapDialog
from interface_dialog import NetworkInterfaceDialog
from ui_theme import DARK_STYLESHEET, LIGHT_STYLESHEET, LivePingOscilloscope
from version import APP_RELEASE_DATE, APP_VERSION, VERSION_HISTORY, get_full_version, get_short_version
from watchdog_engine import (
    WatchdogDialog,
    WatchdogEvent,
    WatchdogWorker,
    append_watchdog_event,
    load_watchdog_config,
    save_watchdog_config,
    send_desktop_notification,
)
from topology_widget import NetworkTopologyWidget
from network_guard_engine import NETWORK_GUARD, NetworkGuardDialog
from snapshot_engine import SNAPSHOT_MANAGER, SnapshotDiffDialog
from upnp_engine import discover_upnp_devices
from traceroute_dialog import TracerouteDialog

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
            self.progress_updated.emit(0, len(self.ip_list), tr("stat_onvif_discovery", "Buscando câmeras ONVIF (WS-Discovery)..."))
            try:
                onvif_cache = discover_onvif_devices(timeout=1.2)
            except Exception as e:
                print(f"ONVIF discovery error: {e}")

        upnp_cache = {}
        if self._is_running:
            self.progress_updated.emit(0, len(self.ip_list), tr("stat_upnp_discovery", "Buscando ativos UPnP / SSDP (UDP 1900)..."))
            try:
                upnp_cache = discover_upnp_devices(timeout=0.9)
            except Exception as e:
                print(f"UPnP discovery error: {e}")

        found_count = 0
        total = len(self.ip_list)
        processed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {
                executor.submit(scan_single_ip, ip, arp_cache, self.local_info, onvif_cache, False, upnp_cache): ip
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
            if ip and self._is_running:
                alive, rtt, ttl, method = probe_ping(ip, timeout_ms=450)
                if ip == self.target_ip and self._is_running:
                    self.sample_ready.emit(ip, rtt if alive else -1.0, ttl, method)
            for _ in range(10):
                if not self._is_running:
                    break
                time.sleep(0.05)


class PingSweepWorker(QThread):
    batch_finished = pyqtSignal(list)

    def __init__(self, ips: List[str]):
        super().__init__()
        self.ips = ips
        self._is_running = True

    def stop(self):
        self._is_running = False

    def run(self):
        def ping_one(ip_addr):
            if not self._is_running:
                return ip_addr, -1.0
            alive, rtt, _, _ = probe_ping(ip_addr, timeout_ms=250)
            return ip_addr, rtt if alive else -1.0

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(self.ips) or 1)) as ex:
            for ip, rtt in ex.map(ping_one, self.ips):
                if not self._is_running:
                    break
                results.append((ip, rtt))
        if self._is_running:
            self.batch_finished.emit(results)


class AppUpdateWorker(QThread):
    progress_status = pyqtSignal(str)
    update_finished = pyqtSignal(bool, str, bool)  # success, message, needs_restart

    def __init__(self, repo_dir: str):
        super().__init__()
        self.repo_dir = repo_dir

    def run(self):
        try:
            self.progress_status.emit("Verificando ambiente de instalação...")
            is_git = False
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "--is-inside-work-tree"],
                    cwd=self.repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=4
                )
                if res.returncode == 0 and "true" in res.stdout:
                    is_git = True
            except Exception:
                is_git = False

            if is_git:
                self._update_via_git()
            else:
                self._update_via_http_zip()
        except Exception as e:
            self.update_finished.emit(False, f"Erro durante o processo de atualização:\n{str(e)}", False)

    def _update_via_git(self):
        old_ver = get_full_version(self.repo_dir)
        self.progress_status.emit(f"Versão atual instalada: {old_ver}\nConsultando atualizações no GitHub...")
        fetch_res = subprocess.run(
            ["git", "fetch", "origin", "main"],
            cwd=self.repo_dir,
            capture_output=True,
            text=True,
            timeout=15
        )
        if fetch_res.returncode != 0:
            err_msg = fetch_res.stderr.strip() or fetch_res.stdout.strip()
            self.update_finished.emit(False, f"Não foi possível conectar ao GitHub:\n{err_msg}", False)
            return

        rev_res = subprocess.run(
            ["git", "rev-list", "HEAD..origin/main", "--count"],
            cwd=self.repo_dir,
            capture_output=True,
            text=True,
            timeout=5
        )
        count = 0
        if rev_res.returncode == 0:
            try:
                count = int(rev_res.stdout.strip())
            except ValueError:
                count = 0

        if count == 0:
            self.progress_status.emit(f"O aplicativo já está na versão mais recente: {old_ver}")
            self.update_finished.emit(
                True,
                f"O IP Scan IGT já está na versão mais recente!\n\n"
                f"• Versão Atual: {old_ver}\n"
                f"Nenhuma nova atualização disponível no momento.",
                False
            )
            return

        self.progress_status.emit(f"Baixando e aplicando {count} nova(s) atualização(ões)...")
        pull_res = subprocess.run(
            ["git", "pull", "--rebase", "origin", "main"],
            cwd=self.repo_dir,
            capture_output=True,
            text=True,
            timeout=25
        )
        if pull_res.returncode != 0:
            pull_res = subprocess.run(
                ["git", "pull", "origin", "main"],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                timeout=25
            )
            if pull_res.returncode != 0:
                err_str = pull_res.stderr.strip() or pull_res.stdout.strip()
                self.update_finished.emit(False, f"Erro ao aplicar atualizações via git pull:\n{err_str}", False)
                return

        self._update_python_dependencies()

        new_ver = get_full_version(self.repo_dir)
        self.progress_status.emit(f"Atualização concluída: {old_ver} ➔ {new_ver}")
        self.update_finished.emit(
            True,
            f"O IP Scan IGT foi atualizado com sucesso!\n\n"
            f"• Versão Anterior: {old_ver}\n"
            f"• Nova Versão Instalada: {new_ver}\n"
            f"• {count} melhoria(s) e alterações integradas.\n\n"
            f"Deseja reiniciar o aplicativo agora para carregar a nova versão?",
            True
        )

    def _update_via_http_zip(self):
        old_ver = get_full_version(self.repo_dir)
        self.progress_status.emit(f"Versão atual instalada: {old_ver}\nConsultando atualizações no GitHub...")

        # 1. Se for aplicativo compilado (.exe / PyInstaller)
        is_frozen = getattr(sys, "frozen", False)
        if is_frozen:
            self.progress_status.emit("Consultando versões compiladas no GitHub Releases...")
            try:
                rel_url = "https://api.github.com/repos/icarogabrielc85-ai/ip-scan-igt/releases/latest"
                req = urllib.request.Request(rel_url, headers={"User-Agent": "IPScanIGT-Updater"})
                with robust_urlopen(req, timeout=8) as resp:
                    rel_data = json.loads(resp.read().decode("utf-8"))
                    latest_tag = rel_data.get("tag_name", "").lstrip("v")
                    html_url = rel_data.get("html_url", "https://github.com/icarogabrielc85-ai/ip-scan-igt/releases")

                    from version import APP_VERSION
                    if latest_tag and latest_tag != APP_VERSION:
                        self.update_finished.emit(
                            True,
                            f"Nova versão compilada disponível: v{latest_tag}!\n\n"
                            f"• Versão Atual: v{APP_VERSION}\n"
                            f"• Nova Versão: v{latest_tag}\n\n"
                            f"Clique em OK para abrir a página oficial de download no navegador.",
                            False
                        )
                        QDesktopServices.openUrl(QUrl(html_url))
                        return
                    else:
                        self.update_finished.emit(
                            True,
                            f"O IP Scan IGT já está na versão compilada mais recente (v{APP_VERSION})!",
                            False
                        )
                        return
            except Exception as e:
                self.update_finished.emit(
                    False,
                    f"Não foi possível consultar os lançamentos no GitHub Releases:\n{str(e)}\n\n"
                    f"Acesse diretamente: https://github.com/icarogabrielc85-ai/ip-scan-igt/releases",
                    False
                )
                return

        # 2. Instalação de código-fonte (Windows ou Linux sem Git)
        self.progress_status.emit("Consultando último commit no repositório GitHub...")
        meta_file = os.path.join(self.repo_dir, ".version_meta.json")
        local_sha = ""
        if os.path.exists(meta_file):
            try:
                with open(meta_file, "r", encoding="utf-8") as mf:
                    local_sha = json.load(mf).get("commit_sha", "").strip()
            except Exception:
                pass

        latest_sha = ""
        latest_msg = ""
        commit_date = ""

        try:
            api_url = "https://api.github.com/repos/icarogabrielc85-ai/ip-scan-igt/commits/main"
            req = urllib.request.Request(api_url, headers={"User-Agent": "IPScanIGT-Updater"})
            with robust_urlopen(req, timeout=8) as resp:
                c_data = json.loads(resp.read().decode("utf-8"))
                latest_sha = c_data.get("sha", "")[:7]
                latest_msg = c_data.get("commit", {}).get("message", "").split("\n")[0]
                commit_date = c_data.get("commit", {}).get("author", {}).get("date", "")
        except Exception:
            pass

        # Se já temos o commit_sha registrado e é igual ao mais recente
        if local_sha and latest_sha and local_sha == latest_sha:
            self.progress_status.emit(f"O aplicativo já está na versão mais recente: {old_ver}")
            self.update_finished.emit(
                True,
                f"O IP Scan IGT já está na versão mais recente!\n\n"
                f"• Versão Atual: {old_ver}\n"
                f"Nenhuma nova atualização disponível no momento.",
                False
            )
            return

        # 3. Baixar pacote ZIP com o repositório completo do GitHub
        self.progress_status.emit("Baixando pacote de atualização do GitHub...")
        zip_url = "https://github.com/icarogabrielc85-ai/ip-scan-igt/archive/refs/heads/main.zip"
        req = urllib.request.Request(zip_url, headers={"User-Agent": "IPScanIGT-Updater"})
        try:
            with robust_urlopen(req, timeout=35) as resp:
                zip_data = resp.read()
        except Exception as e:
            self.update_finished.emit(
                False,
                f"Falha ao baixar o arquivo de atualização do GitHub:\n{str(e)}\n\n"
                f"Verifique sua conexão com a internet.",
                False
            )
            return

        # 4. Extrair e sobrescrever arquivos da aplicação
        self.progress_status.emit("Extraindo e aplicando arquivos da nova versão...")
        try:
            count_files = 0
            with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
                namelist = z.namelist()
                prefix = namelist[0].split("/")[0] + "/" if namelist and "/" in namelist[0] else "ip-scan-igt-main/"
                for member in z.infolist():
                    if not member.filename.startswith(prefix):
                        continue
                    rel_path = member.filename[len(prefix):]
                    if not rel_path or rel_path.endswith("/"):
                        continue

                    target_path = os.path.join(self.repo_dir, rel_path)
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with z.open(member) as src_file, open(target_path, "wb") as dst_file:
                        dst_file.write(src_file.read())
                    count_files += 1

            if latest_sha:
                try:
                    with open(meta_file, "w", encoding="utf-8") as mf:
                        json.dump(
                            {
                                "commit_sha": latest_sha,
                                "date": commit_date,
                                "message": latest_msg,
                            },
                            mf,
                            indent=2
                        )
                except Exception:
                    pass
        except Exception as e:
            self.update_finished.emit(
                False,
                f"Falha ao extrair os arquivos da atualização:\n{str(e)}",
                False
            )
            return

        # 5. Atualizar dependências Python se houver requirements
        self._update_python_dependencies()

        new_ver = get_full_version(self.repo_dir)
        self.progress_status.emit(f"Atualização concluída: {new_ver}")
        self.update_finished.emit(
            True,
            f"O IP Scan IGT foi atualizado com sucesso via download direto!\n\n"
            f"• Versão Anterior: {old_ver}\n"
            f"• Nova Versão Instalada: {new_ver}\n"
            f"• {count_files} arquivo(s) atualizado(s) diretamente do GitHub.\n"
            + (f"• Último commit: {latest_sha} — {latest_msg}\n\n" if latest_sha else "\n") +
            f"Deseja reiniciar o aplicativo agora para carregar a nova versão?",
            True
        )

    def _update_python_dependencies(self):
        self.progress_status.emit("Verificando dependências Python...")
        req_file = os.path.join(self.repo_dir, "requirements.txt")
        if os.path.exists(req_file):
            try:
                pip_args = [sys.executable, "-m", "pip", "install", "-r", req_file, "--quiet"]
                if not IS_WINDOWS:
                    pip_args.extend(["--break-system-packages", "--user"])
                subprocess.run(pip_args, cwd=self.repo_dir, timeout=30)
            except Exception:
                pass


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
        self.setWindowTitle(f"IP Scan IGT — {get_full_version()}")
        primary = QApplication.primaryScreen()
        if primary:
            geo = primary.availableGeometry()
            self.setGeometry(geo)
        else:
            self.resize(1366, 768)

        # Iniciar em tela cheia / maximizado por padrão
        self.setWindowState(Qt.WindowMaximized)
        QTimer.singleShot(0, self.showMaximized)

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

        self.current_lang = get_current_language()
        self.watchdog_cfg = load_watchdog_config()
        self.watchdog_worker = WatchdogWorker(
            interval_sec=self.watchdog_cfg.get("interval_sec", 15),
            failure_threshold=self.watchdog_cfg.get("failure_threshold", 2),
        )
        self.watchdog_worker.host_checked.connect(self.on_watchdog_host_checked)
        self.watchdog_worker.state_changed.connect(self.on_watchdog_state_changed)
        self.watchdog_worker.cycle_finished.connect(self.on_watchdog_cycle_finished)
        self.tray_icon: Optional[QSystemTrayIcon] = None

        self.init_menu_bar()
        self.init_ui()
        self.load_favorites()
        self.init_system_tray()
        self.sync_watchdog_state()
        self.apply_theme()
        self.retranslate_ui()

    def init_menu_bar(self):
        menu_bar = self.menuBar()

        # 1. Arquivo
        self.menu_file = menu_bar.addMenu(tr("menu_file"))
        self.act_csv = QAction(tr("export_csv"), self)
        self.act_csv.setShortcut("Ctrl+S")
        self.act_csv.triggered.connect(lambda: self.export_results("csv"))
        self.menu_file.addAction(self.act_csv)

        self.act_html = QAction(tr("export_html"), self)
        self.act_html.setShortcut("Ctrl+H")
        self.act_html.triggered.connect(lambda: self.export_results("html"))
        self.menu_file.addAction(self.act_html)

        self.act_json = QAction(tr("export_json"), self)
        self.act_json.triggered.connect(lambda: self.export_results("json"))
        self.menu_file.addAction(self.act_json)

        self.act_txt = QAction(tr("export_txt"), self)
        self.act_txt.triggered.connect(lambda: self.export_results("txt"))
        self.menu_file.addAction(self.act_txt)

        self.menu_file.addSeparator()
        self.act_exit = QAction(tr("exit"), self)
        self.act_exit.setShortcut("Ctrl+Q")
        self.act_exit.triggered.connect(self.close)
        self.menu_file.addAction(self.act_exit)

        # 2. Ações
        self.menu_actions = menu_bar.addMenu(tr("menu_actions"))
        self.act_scan = QAction(tr("scan_network"), self)
        self.act_scan.setShortcut("F5")
        self.act_scan.triggered.connect(self.toggle_scan)
        self.menu_actions.addAction(self.act_scan)

        self.act_stop = QAction(tr("stop_scan"), self)
        self.act_stop.setShortcut("Esc")
        self.act_stop.triggered.connect(self.toggle_scan)
        self.menu_actions.addAction(self.act_stop)

        self.menu_actions.addSeparator()
        self.act_expand = QAction(tr("expand_all"), self)
        self.act_expand.setShortcut("Ctrl+E")
        self.act_expand.triggered.connect(self.expand_all_results)
        self.menu_actions.addAction(self.act_expand)

        self.act_collapse = QAction(tr("collapse_all"), self)
        self.act_collapse.setShortcut("Ctrl+R")
        self.act_collapse.triggered.connect(self.collapse_all_results)
        self.menu_actions.addAction(self.act_collapse)

        self.menu_actions.addSeparator()
        self.act_add_fav = QAction(tr("add_favorite"), self)
        self.act_add_fav.setShortcut("Ctrl+D")
        self.act_add_fav.triggered.connect(self.add_selected_to_favorites)
        self.menu_actions.addAction(self.act_add_fav)

        self.act_scan_fav = QAction(tr("scan_favorites"), self)
        self.act_scan_fav.triggered.connect(self.scan_favorites_only)
        self.menu_actions.addAction(self.act_scan_fav)

        self.menu_actions.addSeparator()
        self.act_iface = QAction(tr("select_interface"), self)
        self.act_iface.setShortcut("Ctrl+I")
        self.act_iface.triggered.connect(self.open_interface_dialog)
        self.menu_actions.addAction(self.act_iface)

        self.act_nmap = QAction(tr("nmap_scan"), self)
        self.act_nmap.setShortcut("Ctrl+N")
        self.act_nmap.triggered.connect(self.action_open_nmap)
        self.menu_actions.addAction(self.act_nmap)

        self.menu_actions.addSeparator()
        self.act_rdp = QAction(tr("connect_rdp"), self)
        self.act_rdp.triggered.connect(self.action_open_rdp)
        self.menu_actions.addAction(self.act_rdp)

        self.act_ssh = QAction(tr("connect_ssh"), self)
        self.act_ssh.triggered.connect(self.action_open_ssh)
        self.menu_actions.addAction(self.act_ssh)

        self.act_wol = QAction(tr("wake_on_lan"), self)
        self.act_wol.triggered.connect(self.action_open_wol)
        self.menu_actions.addAction(self.act_wol)

        self.act_video_cfg = QAction(tr("config_video"), self)
        self.act_video_cfg.triggered.connect(self.open_camera_config_dialog)
        self.menu_actions.addAction(self.act_video_cfg)

        self.act_doctor_act = QAction(tr("system_doctor"), self)
        self.act_doctor_act.triggered.connect(self.open_system_doctor_dialog)
        self.menu_actions.addAction(self.act_doctor_act)

        self.act_net_test = QAction(tr("internet_test"), self)
        self.act_net_test.triggered.connect(self.open_internet_test_dialog)
        self.menu_actions.addAction(self.act_net_test)

        self.menu_actions.addSeparator()
        self.act_guard = QAction(tr("menu_network_guard", "🛡️ Network Guard (Intrusos & ARP Spoofing)..."), self)
        self.act_guard.triggered.connect(self.open_network_guard_dialog)
        self.menu_actions.addAction(self.act_guard)

        self.act_snapshots = QAction(tr("menu_snapshots", "📸 Snapshots & Comparador de Mudanças (Diff)..."), self)
        self.act_snapshots.triggered.connect(self.open_snapshot_diff_dialog)
        self.menu_actions.addAction(self.act_snapshots)

        self.act_traceroute = QAction(tr("menu_traceroute", "🧭 Traceroute Visual (Rota TTL)..."), self)
        self.act_traceroute.triggered.connect(self.action_open_traceroute)
        self.menu_actions.addAction(self.act_traceroute)

        # 3. Exibir
        self.menu_view = menu_bar.addMenu(tr("menu_view"))
        self.act_toggle_bottom = QAction(tr("panel_ping"), self)
        self.act_toggle_bottom.setCheckable(True)
        self.act_toggle_bottom.setChecked(True)
        self.act_toggle_bottom.setShortcut("Ctrl+P")
        self.act_toggle_bottom.triggered.connect(self.toggle_bottom_panel)
        self.menu_view.addAction(self.act_toggle_bottom)

        self.menu_view.addSeparator()
        self.act_theme = QAction(tr("toggle_theme"), self)
        self.act_theme.setShortcut("Ctrl+T")
        self.act_theme.triggered.connect(self.toggle_theme)
        self.menu_view.addAction(self.act_theme)

        # 4. Idioma / Language (9 idiomas completos)
        self.menu_lang = menu_bar.addMenu(tr("menu_lang"))
        self.lang_action_group = QActionGroup(self)
        self.lang_action_group.setExclusive(True)
        self.lang_actions = {}
        for code, lang_info in SUPPORTED_LANGUAGES.items():
            act = QAction(f"{lang_info['flag']}  {lang_info['native']}", self)
            act.setCheckable(True)
            if code == self.current_lang:
                act.setChecked(True)
            act.triggered.connect(lambda checked, c=code: self.change_language(c))
            self.lang_action_group.addAction(act)
            self.menu_lang.addAction(act)
            self.lang_actions[code] = act

        # 5. Ajuda
        self.menu_help = menu_bar.addMenu(tr("menu_help"))
        self.act_net_test_help = QAction(tr("internet_test"), self)
        self.act_net_test_help.triggered.connect(self.open_internet_test_dialog)
        self.menu_help.addAction(self.act_net_test_help)

        self.act_doctor = QAction(tr("system_doctor"), self)
        self.act_doctor.triggered.connect(self.open_system_doctor_dialog)
        self.menu_help.addAction(self.act_doctor)

        self.act_update = QAction(tr("check_updates"), self)
        self.act_update.triggered.connect(self.check_and_apply_update)
        self.menu_help.addAction(self.act_update)

        self.act_changelog = QAction("Histórico de Versões e Atualizações...", self)
        self.act_changelog.triggered.connect(self.show_changelog_dialog)
        self.menu_help.addAction(self.act_changelog)
        self.menu_help.addSeparator()

        self.act_about = QAction(tr("about"), self)
        self.act_about.triggered.connect(self.show_about_dialog)
        self.menu_help.addAction(self.act_about)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # =========================================================================
        # 1. TIER 1 - MAIN HEADER BAR (Brand, Scan, IP Range, Mask, Search, Update)
        # =========================================================================
        top_bar = QFrame()
        top_bar.setObjectName("topBar")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(12, 6, 12, 6)
        top_layout.setSpacing(8)

        # Brand logo + Program Name + Version Tag
        brand_frame = QFrame()
        brand_frame.setObjectName("brandFrame")
        brand_layout = QHBoxLayout(brand_frame)
        brand_layout.setContentsMargins(0, 0, 4, 0)
        brand_layout.setSpacing(6)

        icon_lbl = QLabel()
        icon_path = get_resource_path("icon.png")
        if os.path.exists(icon_path):
            pix = QPixmap(icon_path).scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            icon_lbl.setPixmap(pix)
        brand_layout.addWidget(icon_lbl)

        lbl_app_name = QLabel("IP Scan IGT")
        lbl_app_name.setObjectName("lblAppName")
        brand_layout.addWidget(lbl_app_name)

        self.lbl_version_badge = QLabel(get_short_version())
        self.lbl_version_badge.setObjectName("lblVersionBadge")
        self.lbl_version_badge.setFixedHeight(22)
        self.lbl_version_badge.setToolTip(f"Versão Instalada: {get_full_version()}\nClique para ver o histórico completo de atualizações.")
        self.lbl_version_badge.setCursor(Qt.PointingHandCursor)
        self.lbl_version_badge.mousePressEvent = lambda e: self.show_changelog_dialog()
        brand_layout.addWidget(self.lbl_version_badge)

        top_layout.addWidget(brand_frame)

        # Subtle vertical separator line
        sep_brand = QFrame()
        sep_brand.setFrameShape(QFrame.VLine)
        sep_brand.setFrameShadow(QFrame.Sunken)
        sep_brand.setStyleSheet("color: #475569; margin: 4px 2px;")
        top_layout.addWidget(sep_brand)

        # Big "Verificar" green button
        self.btn_start = QPushButton("▶  Verificar")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.setMinimumHeight(34)
        self.btn_start.setMinimumWidth(115)
        self.btn_start.clicked.connect(self.toggle_scan)
        top_layout.addWidget(self.btn_start)

        # "IP" button with network interface picker
        self.btn_subnet = QPushButton("🖧 IP ▾")
        self.btn_subnet.setObjectName("btnSubnet")
        self.btn_subnet.setMinimumHeight(34)
        self.btn_subnet.setMinimumWidth(68)
        self.btn_subnet.setToolTip("Preencher faixa IP e selecionar Placa de Rede")
        self.btn_subnet.clicked.connect(self.show_interface_menu)
        top_layout.addWidget(self.btn_subnet)

        # Range inputs
        self.lbl_from = QLabel("Faixa:")
        self.lbl_from.setStyleSheet("font-weight: 600; font-size: 12px;")
        top_layout.addWidget(self.lbl_from)

        self.txt_start_ip = QLineEdit(self.local_info.get("start_ip", "192.168.1.1"))
        self.txt_start_ip.setObjectName("txtStartIp")
        self.txt_start_ip.setFixedWidth(135)
        self.txt_start_ip.setFixedHeight(30)
        self.txt_start_ip.setAlignment(Qt.AlignCenter)
        self.txt_start_ip.setToolTip("Endereço IP inicial da faixa de varredura")
        top_layout.addWidget(self.txt_start_ip)

        lbl_sep = QLabel("➔")
        lbl_sep.setStyleSheet("font-weight: bold; font-size: 13px; color: #64748b; margin: 0 1px;")
        top_layout.addWidget(lbl_sep)

        self.txt_end_ip = QLineEdit(self.local_info.get("end_ip", "192.168.1.254"))
        self.txt_end_ip.setObjectName("txtEndIp")
        self.txt_end_ip.setFixedWidth(135)
        self.txt_end_ip.setFixedHeight(30)
        self.txt_end_ip.setAlignment(Qt.AlignCenter)
        self.txt_end_ip.setToolTip("Endereço IP final da faixa de varredura")
        top_layout.addWidget(self.txt_end_ip)

        self.lbl_mask = QLabel("Máscara:")
        self.lbl_mask.setStyleSheet("font-weight: 600; font-size: 12px;")
        top_layout.addWidget(self.lbl_mask)

        self.combo_mask = QComboBox()
        self.combo_mask.setMinimumWidth(195)
        self.combo_mask.setFixedHeight(30)
        self.combo_mask.setToolTip("Máscara de sub-rede / Prefixo CIDR da rede")
        self.populate_mask_combo()
        self.set_mask_cidr(self.local_info.get("cidr", 24))
        self.combo_mask.currentIndexChanged.connect(self.on_mask_changed)
        top_layout.addWidget(self.combo_mask)

        self.txt_start_ip.textChanged.connect(self.auto_detect_mask_from_inputs)
        self.txt_end_ip.textChanged.connect(self.auto_detect_mask_from_inputs)

        # Search filter
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Filtrar (Nome, IP, MAC)...")
        self.txt_search.setClearButtonEnabled(True)
        self.txt_search.setFixedHeight(30)
        self.txt_search.setMinimumWidth(130)
        self.txt_search.setToolTip("Filtrar dispositivos por nome, IP, MAC ou fabricante")
        self.txt_search.textChanged.connect(self.filter_current_tree)
        top_layout.addWidget(self.txt_search, 1)

        # 1-Click Update Button
        self.btn_update = QPushButton("🔄 Atualizar")
        self.btn_update.setObjectName("btnUpdate")
        self.btn_update.setFixedHeight(30)
        self.btn_update.setMinimumWidth(90)
        self.btn_update.setToolTip("Verificar e aplicar atualizações do repositório em 1 clique")
        self.btn_update.clicked.connect(self.check_and_apply_update)
        top_layout.addWidget(self.btn_update)

        main_layout.addWidget(top_bar)

        # =========================================================================
        # 2. TIER 2 - RIBBON UTILITY BAR (Expand/Collapse, ONVIF, Nmap, Reports, KPIs)
        # =========================================================================
        ribbon_bar = QFrame()
        ribbon_bar.setObjectName("ribbonBar")
        ribbon_layout = QHBoxLayout(ribbon_bar)
        ribbon_layout.setContentsMargins(8, 3, 8, 3)
        ribbon_layout.setSpacing(4)

        # Quick Expand/Collapse buttons
        self.btn_expand = QPushButton("⊞ Expandir")
        self.btn_expand.setObjectName("ribbonBtn")
        self.btn_expand.setFixedHeight(28)
        self.btn_expand.setToolTip("Expandir todos os serviços e recursos de todos os hosts [+] (Ctrl+E)")
        self.btn_expand.clicked.connect(self.expand_all_results)
        ribbon_layout.addWidget(self.btn_expand)

        self.btn_collapse = QPushButton("⊟ Recolher")
        self.btn_collapse.setObjectName("ribbonBtn")
        self.btn_collapse.setFixedHeight(28)
        self.btn_collapse.setToolTip("Recolher todos os dispositivos [-] (Ctrl+R)")
        self.btn_collapse.clicked.connect(self.collapse_all_results)
        ribbon_layout.addWidget(self.btn_collapse)

        # Divider
        sep_r1 = QFrame()
        sep_r1.setFrameShape(QFrame.VLine)
        sep_r1.setFrameShadow(QFrame.Sunken)
        sep_r1.setStyleSheet("color: #475569; margin: 3px 2px;")
        ribbon_layout.addWidget(sep_r1)

        # ONVIF auto-discovery toggle
        self.chk_onvif = QCheckBox("🎥 ONVIF")
        self.chk_onvif.setChecked(True)
        self.chk_onvif.setFixedHeight(28)
        self.chk_onvif.setStyleSheet("font-weight: 600; padding: 0 4px;")
        self.chk_onvif.setToolTip("Descobrir câmeras IP e gravadores NVR via protocolo ONVIF (WS-Discovery)")
        ribbon_layout.addWidget(self.chk_onvif)

        # Camera Video resolution / playback config button
        self.btn_camera_cfg = QPushButton("⚙️ Vídeo")
        self.btn_camera_cfg.setObjectName("ribbonBtn")
        self.btn_camera_cfg.setFixedHeight(28)
        self.btn_camera_cfg.setToolTip("Configurar resolução de exibição, player preferido e latência de câmeras (RTSP)")
        self.btn_camera_cfg.clicked.connect(self.open_camera_config_dialog)
        ribbon_layout.addWidget(self.btn_camera_cfg)

        # Nmap Scanner tool button
        self.btn_nmap = QPushButton("🔍 Nmap")
        self.btn_nmap.setObjectName("ribbonBtn")
        self.btn_nmap.setFixedHeight(28)
        self.btn_nmap.setToolTip("Abrir console de auditoria profunda com Nmap (Ctrl+N)")
        self.btn_nmap.clicked.connect(self.action_open_nmap)
        ribbon_layout.addWidget(self.btn_nmap)

        # Internet Health & DNS Quality Test button
        self.btn_net_test = QPushButton("🌐 Internet")
        self.btn_net_test.setObjectName("ribbonBtn")
        self.btn_net_test.setFixedHeight(28)
        self.btn_net_test.setToolTip("Testar conexão de internet, gateway, DNS da placa e benchmark dos principais servidores DNS mundiais")
        self.btn_net_test.clicked.connect(self.open_internet_test_dialog)
        ribbon_layout.addWidget(self.btn_net_test)

        # Watchdog Continuous Monitoring button
        self.btn_watchdog = QPushButton("🛡️ Watchdog")
        self.btn_watchdog.setObjectName("ribbonBtn")
        self.btn_watchdog.setFixedHeight(28)
        self.btn_watchdog.setToolTip("Monitoramento contínuo em segundo plano dos dispositivos em Favoritos com alertas nativos no desktop")
        self.btn_watchdog.clicked.connect(self.open_watchdog_dialog)
        ribbon_layout.addWidget(self.btn_watchdog)

        # Network Guard (ARP Spoofing / IP Conflict / Intruder Detection)
        self.btn_guard = QPushButton("🚨 Guard")
        self.btn_guard.setObjectName("ribbonBtn")
        self.btn_guard.setFixedHeight(28)
        self.btn_guard.setToolTip("Detecção de Intrusos (Novos MACs), Conflitos de IP e ataques de ARP Spoofing")
        self.btn_guard.clicked.connect(self.open_network_guard_dialog)
        ribbon_layout.addWidget(self.btn_guard)

        # Audit Snapshots & Baseline Diff button
        self.btn_snapshots = QPushButton("📸 Snapshots")
        self.btn_snapshots.setObjectName("ribbonBtn")
        self.btn_snapshots.setFixedHeight(28)
        self.btn_snapshots.setToolTip("Salvar Snapshot Base da rede e comparar mudanças (Novos hosts, Ausentes, Portas e CVEs)")
        self.btn_snapshots.clicked.connect(self.open_snapshot_diff_dialog)
        ribbon_layout.addWidget(self.btn_snapshots)

        # Executive Report Export Menu button
        self.btn_report = QPushButton("📑 Relatório ▾")
        self.btn_report.setObjectName("ribbonBtn")
        self.btn_report.setFixedHeight(28)
        self.btn_report.setToolTip("Gerar relatório executivo profissional em HTML/PDF, planilha CSV, JSON ou TXT")
        self.btn_report.clicked.connect(self.show_report_menu)
        ribbon_layout.addWidget(self.btn_report)

        # Divider
        sep_r2 = QFrame()
        sep_r2.setFrameShape(QFrame.VLine)
        sep_r2.setFrameShadow(QFrame.Sunken)
        sep_r2.setStyleSheet("color: #475569; margin: 3px 2px;")
        ribbon_layout.addWidget(sep_r2)

        # Bottom panel toggle button
        self.btn_panel_toggle = QPushButton("📈 Monitor")
        self.btn_panel_toggle.setObjectName("ribbonBtn")
        self.btn_panel_toggle.setFixedHeight(28)
        self.btn_panel_toggle.setCheckable(True)
        self.btn_panel_toggle.setChecked(True)
        self.btn_panel_toggle.setToolTip("Exibir ou ocultar o painel inferior de osciloscópio e detalhes (Ctrl+P)")
        self.btn_panel_toggle.clicked.connect(self.toggle_bottom_panel)
        ribbon_layout.addWidget(self.btn_panel_toggle)

        # Quick Theme button
        self.btn_theme = QPushButton("🌙 Escuro")
        self.btn_theme.setObjectName("ribbonBtn")
        self.btn_theme.setFixedHeight(28)
        self.btn_theme.setToolTip("Alternar Tema Claro / Escuro (Ctrl+T)")
        self.btn_theme.clicked.connect(self.toggle_theme)
        ribbon_layout.addWidget(self.btn_theme)

        # Seletor Rápido de Idioma na Barra de Ferramentas (9 idiomas)
        self.combo_lang = QComboBox()
        self.combo_lang.setObjectName("comboLang")
        self.combo_lang.setFixedHeight(28)
        self.combo_lang.setMinimumWidth(135)
        self.combo_lang.setToolTip("Alterar idioma da aplicação (Change application language)")
        for code, lang_info in SUPPORTED_LANGUAGES.items():
            self.combo_lang.addItem(f"{lang_info['flag']}  {lang_info['native']}", code)
        idx_lang = self.combo_lang.findData(self.current_lang)
        if idx_lang >= 0:
            self.combo_lang.setCurrentIndex(idx_lang)
        self.combo_lang.currentIndexChanged.connect(self.on_lang_combo_changed)
        ribbon_layout.addWidget(self.combo_lang)

        # Stretch spacer
        ribbon_layout.addStretch()

        # Real-time KPI Dashboard Badges
        self.kpi_online = QLabel("● 0 Online")
        self.kpi_online.setObjectName("kpiOnline")
        self.kpi_online.setAlignment(Qt.AlignCenter)
        self.kpi_online.setFixedHeight(24)
        ribbon_layout.addWidget(self.kpi_online)

        self.kpi_latency = QLabel("⚡ -- ms")
        self.kpi_latency.setObjectName("kpiLatency")
        self.kpi_latency.setAlignment(Qt.AlignCenter)
        self.kpi_latency.setFixedHeight(24)
        ribbon_layout.addWidget(self.kpi_latency)

        self.kpi_services = QLabel("🛡️ 0 Serviços")
        self.kpi_services.setObjectName("kpiServices")
        self.kpi_services.setAlignment(Qt.AlignCenter)
        self.kpi_services.setFixedHeight(24)
        ribbon_layout.addWidget(self.kpi_services)

        self.kpi_cves = QLabel("⚠️ 0 CVEs")
        self.kpi_cves.setObjectName("kpiCves")
        self.kpi_cves.setAlignment(Qt.AlignCenter)
        self.kpi_cves.setFixedHeight(24)
        self.kpi_cves.setStyleSheet(
            "background-color: #fee2e2; color: #991b1b; font-weight: bold; font-size: 11px; padding: 2px 8px; border-radius: 10px; border: 1px solid #fecaca;"
        )
        ribbon_layout.addWidget(self.kpi_cves)

        main_layout.addWidget(ribbon_bar)

        # --- 2. MAIN CENTRAL SPLITTER (Vertical) ---
        self.main_splitter = QSplitter(Qt.Vertical)
        self.main_splitter.setHandleWidth(5)

        # Upper Area: Main Tabs [Resultados], [Favoritos] & [Topologia da Rede]
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

        self.main_tabs.addTab(tab_results, tr("tab_results", "Resultado Scan"))

        # Tab 2: Favoritos
        tab_favorites = QWidget()
        fav_layout = QVBoxLayout(tab_favorites)
        fav_layout.setContentsMargins(6, 6, 6, 6)

        # Toolbar on top of Favorites tab
        fav_bar = QHBoxLayout()
        fav_bar.setContentsMargins(0, 0, 0, 4)
        self.btn_scan_fav = QPushButton("▶  Verificar Favoritos")
        self.btn_scan_fav.setFixedHeight(28)
        self.btn_scan_fav.clicked.connect(self.scan_favorites_only)
        self.btn_del_fav = QPushButton("Remover Selecionado")
        self.btn_del_fav.setFixedHeight(28)
        self.btn_del_fav.clicked.connect(self.remove_selected_favorite)
        self.btn_clear_fav = QPushButton("Limpar Todos")
        self.btn_clear_fav.setFixedHeight(28)
        self.btn_clear_fav.clicked.connect(self.clear_all_favorites)

        self.btn_fav_watchdog = QPushButton("🛡️ Watchdog Contínuo: OFF")
        self.btn_fav_watchdog.setFixedHeight(28)
        self.btn_fav_watchdog.setCheckable(True)
        self.btn_fav_watchdog.setToolTip("Ativar/Desativar monitoramento contínuo de ping em segundo plano para os Favoritos")
        self.btn_fav_watchdog.clicked.connect(self.toggle_watchdog_quick)

        self.btn_fav_watchdog_log = QPushButton("📋 Eventos & Config...")
        self.btn_fav_watchdog_log.setFixedHeight(28)
        self.btn_fav_watchdog_log.clicked.connect(self.open_watchdog_dialog)

        fav_bar.addWidget(self.btn_scan_fav)
        fav_bar.addWidget(self.btn_del_fav)
        fav_bar.addWidget(self.btn_clear_fav)
        fav_bar.addSpacing(12)
        fav_bar.addWidget(self.btn_fav_watchdog)
        fav_bar.addWidget(self.btn_fav_watchdog_log)
        fav_bar.addStretch()
        fav_layout.addLayout(fav_bar)

        self.fav_tree = self.create_device_tree()
        self.fav_tree.itemSelectionChanged.connect(lambda: self.on_tree_selection_changed(self.fav_tree))
        self.fav_tree.itemDoubleClicked.connect(self.on_tree_item_double_clicked)
        self.fav_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.fav_tree.customContextMenuRequested.connect(self.show_fav_context_menu)
        fav_layout.addWidget(self.fav_tree)

        self.main_tabs.addTab(tab_favorites, tr("tab_favorites", "Favoritos"))

        # Tab 3: Mapeamento Visual de Topologia
        self.topology_widget = NetworkTopologyWidget(self, is_dark=self.is_dark_mode)
        self.topology_widget.host_selected.connect(self.on_topology_host_selected)
        self.topology_widget.host_double_clicked.connect(self.on_topology_host_double_clicked)
        self.topology_widget.host_context_menu.connect(self.on_topology_host_context_menu)
        self.main_tabs.addTab(self.topology_widget, tr("tab_topology", "🗺️ Topologia"))

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

        self.btn_hide_panel = QPushButton("✕ Fechar")
        self.btn_hide_panel.setFixedHeight(24)
        self.btn_hide_panel.clicked.connect(lambda: self.set_bottom_panel_visible(False))
        pheader_layout.addWidget(self.btn_hide_panel)
        panel_layout.addWidget(panel_header)

        # Panel content: Left = Oscilloscope, Right = Details Table & Actions
        content_box = QHBoxLayout()
        content_box.setContentsMargins(8, 8, 8, 8)
        content_box.setSpacing(10)

        # Left: Live Ping Sparkline
        self.oscilloscope = LivePingOscilloscope()
        self.oscilloscope.setMinimumHeight(110)
        content_box.addWidget(self.oscilloscope, 5)

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

        # Categorized action buttons organized into 2 clean rows
        # Web category
        btn_open_http = QPushButton("🌐 HTTP")
        btn_open_http.setObjectName("btnActionWeb")
        btn_open_http.setToolTip("Abrir página Web HTTP do dispositivo no navegador padrão")
        btn_open_http.clicked.connect(self.action_open_http)

        btn_open_https = QPushButton("🔒 HTTPS")
        btn_open_https.setObjectName("btnActionWeb")
        btn_open_https.setToolTip("Abrir painel seguro HTTPS do dispositivo no navegador")
        btn_open_https.clicked.connect(self.action_open_https)

        # Remote Access category
        btn_open_smb = QPushButton("📁 SMB")
        btn_open_smb.setObjectName("btnActionRemote")
        btn_open_smb.setToolTip("Acessar compartilhamento de arquivos Windows / Samba da máquina")
        btn_open_smb.clicked.connect(self.action_open_smb)

        btn_rdp = QPushButton("🖥️ RDP")
        btn_rdp.setObjectName("btnActionRemote")
        btn_rdp.setToolTip("Conectar via Área de Trabalho Remota (Remmina / xfreerdp / mstsc)")
        btn_rdp.clicked.connect(self.action_open_rdp)

        btn_ssh = QPushButton("💻 SSH")
        btn_ssh.setObjectName("btnActionRemote")
        btn_ssh.setToolTip("Abrir console de terminal SSH remoto (Konsole / GNOME Terminal / CMD)")
        btn_ssh.clicked.connect(self.action_open_ssh)

        btn_wol = QPushButton("⚡ WoL")
        btn_wol.setObjectName("btnActionRemote")
        btn_wol.setToolTip("Enviar Magic Packet Wake-on-LAN para ligar o computador pelo MAC")
        btn_wol.clicked.connect(self.action_open_wol)

        # Diagnostic & Multimedia category
        btn_rtsp = QPushButton("🎬 RTSP")
        btn_rtsp.setObjectName("btnActionDiag")
        btn_rtsp.setToolTip("Assistir transmissão de vídeo em tempo real da câmera (RTSP / ONVIF)")
        btn_rtsp.clicked.connect(self.action_open_rtsp)

        btn_cam_cfg_bottom = QPushButton("⚙️ Vídeo")
        btn_cam_cfg_bottom.setObjectName("btnActionDiag")
        btn_cam_cfg_bottom.setToolTip("Configurar resolução de exibição e opções de reprodução de câmeras RTSP")
        btn_cam_cfg_bottom.clicked.connect(self.open_camera_config_dialog)

        btn_nmap_bottom = QPushButton("🔍 Nmap")
        btn_nmap_bottom.setObjectName("btnActionDiag")
        btn_nmap_bottom.setToolTip("Executar auditoria profunda de portas com Nmap neste host")
        btn_nmap_bottom.clicked.connect(self.action_open_nmap)

        btn_traceroute_bottom = QPushButton("🧭 Traceroute")
        btn_traceroute_bottom.setObjectName("btnActionDiag")
        btn_traceroute_bottom.setToolTip("Rastrear rota visual (saltos TTL) até este dispositivo")
        btn_traceroute_bottom.clicked.connect(self.action_open_traceroute)

        btn_copy_ip = QPushButton("📋 Copiar IP")
        btn_copy_ip.setObjectName("btnActionDiag")
        btn_copy_ip.setToolTip("Copiar endereço IP para a área de transferência")
        btn_copy_ip.clicked.connect(self.action_copy_current_ip)

        # Row 1: Remote Access & Web
        actions_row1 = QHBoxLayout()
        actions_row1.setSpacing(6)
        actions_row1.addWidget(btn_open_http)
        actions_row1.addWidget(btn_open_https)
        actions_row1.addWidget(btn_open_smb)
        actions_row1.addWidget(btn_rdp)
        actions_row1.addWidget(btn_ssh)

        # Row 2: Diagnostics, Media & Utilities
        actions_row2 = QHBoxLayout()
        actions_row2.setSpacing(6)
        actions_row2.addWidget(btn_wol)
        actions_row2.addWidget(btn_rtsp)
        actions_row2.addWidget(btn_cam_cfg_bottom)
        actions_row2.addWidget(btn_nmap_bottom)
        actions_row2.addWidget(btn_traceroute_bottom)
        actions_row2.addWidget(btn_copy_ip)
        actions_row2.addStretch()

        right_box.addLayout(actions_row1)
        right_box.addLayout(actions_row2)

        content_box.addLayout(right_box, 5)
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
            tr("col_status"),
            tr("col_hostname"),
            tr("col_ip"),
            tr("col_manufacturer"),
            tr("col_mac"),
            tr("col_ping"),
            tr("col_comments"),
        ])
        tree.setAlternatingRowColors(True)
        tree.setUniformRowHeights(True)
        tree.setIndentation(16)

        # Enable clickable column header sorting (Ascending / Descending)
        tree.setSortingEnabled(True)
        tree.header().setSectionsClickable(True)
        tree.header().setSortIndicatorShown(True)
        tree.header().setSortIndicator(2, Qt.AscendingOrder)
        tree.header().sectionClicked.connect(lambda col, t=tree: self.on_tree_header_clicked(t, col))

        tree.header().setSectionResizeMode(0, QHeaderView.Fixed)
        tree.header().resizeSection(0, 56)
        tree.header().setSectionResizeMode(1, QHeaderView.Interactive)
        tree.header().resizeSection(1, 250)
        tree.header().setSectionResizeMode(2, QHeaderView.Interactive)
        tree.header().resizeSection(2, 140)
        tree.header().setSectionResizeMode(3, QHeaderView.Interactive)
        tree.header().resizeSection(3, 195)
        tree.header().setSectionResizeMode(4, QHeaderView.Interactive)
        tree.header().resizeSection(4, 150)
        tree.header().setSectionResizeMode(5, QHeaderView.Interactive)
        tree.header().resizeSection(5, 85)
        tree.header().setSectionResizeMode(6, QHeaderView.Stretch)
        return tree

    def on_lang_combo_changed(self):
        code = self.combo_lang.currentData()
        if code and code != self.current_lang:
            self.change_language(code)

    def change_language(self, lang_code: str):
        if lang_code in SUPPORTED_LANGUAGES:
            self.current_lang = lang_code
            set_current_language(lang_code)

            # Sync combo box
            idx = self.combo_lang.findData(lang_code)
            if idx >= 0 and self.combo_lang.currentIndex() != idx:
                self.combo_lang.blockSignals(True)
                self.combo_lang.setCurrentIndex(idx)
                self.combo_lang.blockSignals(False)

            # Sync menu action check
            act = self.lang_actions.get(lang_code)
            if act and not act.isChecked():
                act.setChecked(True)

            self.retranslate_ui()

    def retranslate_ui(self):
        # Window Title
        self.setWindowTitle(f"IP Scan IGT — {get_full_version()} [{SUPPORTED_LANGUAGES[self.current_lang]['native']}]")

        # Menus
        if hasattr(self, "menu_file"):
            self.menu_file.setTitle(tr("menu_file"))
            self.act_csv.setText(tr("export_csv"))
            self.act_html.setText(tr("export_html"))
            self.act_json.setText(tr("export_json"))
            self.act_txt.setText(tr("export_txt"))
            self.act_exit.setText(tr("exit"))

            self.menu_actions.setTitle(tr("menu_actions"))
            if self.scan_worker and self.scan_worker.isRunning():
                self.act_scan.setText(tr("stop_scan"))
            else:
                self.act_scan.setText(tr("scan_network"))
            self.act_stop.setText(tr("stop_scan"))
            self.act_expand.setText(tr("expand_all"))
            self.act_collapse.setText(tr("collapse_all"))
            self.act_add_fav.setText(tr("add_favorite"))
            self.act_scan_fav.setText(tr("scan_favorites"))
            self.act_iface.setText(tr("select_interface"))
            self.act_nmap.setText(tr("nmap_scan"))
            self.act_rdp.setText(tr("connect_rdp"))
            self.act_ssh.setText(tr("connect_ssh"))
            self.act_wol.setText(tr("wake_on_lan"))
            self.act_video_cfg.setText(tr("config_video"))
            self.act_doctor_act.setText(tr("system_doctor"))
            self.act_net_test.setText(tr("internet_test"))

            self.menu_view.setTitle(tr("menu_view"))
            self.act_toggle_bottom.setText(tr("panel_ping"))
            self.act_theme.setText(tr("toggle_theme"))

            self.menu_lang.setTitle(tr("menu_lang"))

            self.menu_help.setTitle(tr("menu_help"))
            self.act_net_test_help.setText(tr("internet_test"))
            self.act_doctor.setText(tr("system_doctor"))
            self.act_update.setText(tr("check_updates"))
            self.act_about.setText(tr("about"))

        # Ribbon Inputs & Buttons
        if hasattr(self, "btn_start"):
            if self.scan_worker and self.scan_worker.isRunning():
                self.btn_start.setText(f"⏹  {tr('btn_stop')}")
            else:
                self.btn_start.setText(f"▶  {tr('btn_scan')}")

            self.lbl_from.setText(tr("lbl_ip_range"))
            self.lbl_mask.setText(tr("lbl_mask"))
            self.txt_search.setPlaceholderText(f"🔍 {tr('filter_placeholder')}")
            self.btn_update.setText(tr("btn_update"))
            self.btn_expand.setText(tr("btn_expand_short", "⊞ Expandir"))
            self.btn_collapse.setText(tr("btn_collapse_short", "⊟ Recolher"))
            self.btn_camera_cfg.setText(tr("btn_video"))
            self.btn_nmap.setText(tr("btn_nmap"))
            self.btn_net_test.setText(tr("btn_net_test"))
            self.btn_report.setText(tr("report_menu"))
            self.btn_panel_toggle.setText(tr("btn_panel_short", "📈 Monitor"))
            self.btn_theme.setText(tr("theme_light") if self.is_dark_mode else tr("theme_dark"))

        # Tabs
        if hasattr(self, "main_tabs"):
            self.main_tabs.setTabText(0, tr("tab_results", "Resultado Scan"))
            self.main_tabs.setTabText(1, tr("tab_favorites", "Favoritos"))
            if self.main_tabs.count() >= 3:
                self.main_tabs.setTabText(2, tr("tab_topology", "🗺️ Topologia"))

        if hasattr(self, "btn_watchdog"):
            self.btn_watchdog.setText(tr("btn_watchdog", "🛡️ Watchdog"))

        # Favorites Bar
        if hasattr(self, "btn_scan_fav"):
            self.btn_scan_fav.setText(f"▶  {tr('scan_favorites')}")
            self.btn_del_fav.setText(tr("remove_favorite"))
            self.btn_clear_fav.setText(tr("clear_all"))

        # Table Headers
        headers = [
            tr("col_status"),
            tr("col_hostname"),
            tr("col_ip"),
            tr("col_manufacturer"),
            tr("col_mac"),
            tr("col_ping"),
            tr("col_comments"),
        ]
        if hasattr(self, "tree"):
            self.tree.setHeaderLabels(headers)
        if hasattr(self, "fav_tree"):
            self.fav_tree.setHeaderLabels(headers)

        # Bottom Panel Close Button
        if hasattr(self, "btn_hide_panel"):
            self.btn_hide_panel.setText(f"✕ {tr('btn_close')}")

        # Retranslate all existing scanned records in both trees
        if hasattr(self, "tree") and hasattr(self, "records"):
            for rec in self.records.values():
                rec.device_type, rec.os_family = classify_device(rec)
                self.add_or_update_tree_node(self.tree, rec)

        if hasattr(self, "fav_tree") and hasattr(self, "fav_records"):
            for rec in self.fav_records.values():
                rec.device_type, rec.os_family = classify_device(rec)
                self.add_or_update_tree_node(self.fav_tree, rec)

        # Retranslate Details Table & Oscilloscope title
        if hasattr(self, "details_table") and hasattr(self, "lbl_panel_title"):
            tree = self.get_active_tree()
            selected_items = tree.selectedItems() if tree else []
            if selected_items:
                sel_ip = selected_items[0].data(2, Qt.UserRole)
                rec_pool = self.records if tree == self.tree else self.fav_records
                if sel_ip and sel_ip in rec_pool:
                    sel_rec = rec_pool[sel_ip]
                    self.populate_details_table(sel_rec)
                    self.lbl_panel_title.setText(f"● {tr('details_header', 'Monitor de Ping Dinâmico & Detalhes')}: {sel_rec.ip} — {sel_rec.hostname or tr('dev_network_dev', 'Dispositivo')}")
            else:
                self.lbl_panel_title.setText(tr("select_host_prompt", "● Monitor de Ping Dinâmico & Detalhes: [Selecione um dispositivo da lista]"))

        # Status Bar & KPIs
        if hasattr(self, "lbl_stats"):
            if self.scan_worker and self.scan_worker.isRunning():
                pass
            elif hasattr(self, "records"):
                self.update_status_stats()

    def show_report_menu(self):
        menu = QMenu(self)
        act_html = menu.addAction(f"📑  {tr('export_html')}")
        act_html.triggered.connect(lambda: self.export_results("html"))
        act_snap = menu.addAction(f"📸  {tr('menu_snapshots', 'Snapshots & Comparador de Mudanças (Diff)...')}")
        act_snap.triggered.connect(self.open_snapshot_diff_dialog)
        menu.addSeparator()
        act_csv = menu.addAction(f"📊  {tr('export_csv')}")
        act_csv.triggered.connect(lambda: self.export_results("csv"))
        act_json = menu.addAction(f"🗄️  {tr('export_json')}")
        act_json.triggered.connect(lambda: self.export_results("json"))
        act_txt = menu.addAction(f"📝  {tr('export_txt')}")
        act_txt.triggered.connect(lambda: self.export_results("txt"))
        menu.exec_(self.btn_report.mapToGlobal(QPoint(0, self.btn_report.height() + 2)))

    def on_tree_header_clicked(self, tree: QTreeWidget, col: int):
        order = tree.header().sortIndicatorOrder()
        order_str = tr("sort_order_asc", "Crescente ▲") if order == Qt.AscendingOrder else tr("sort_order_desc", "Decrescente ▼")
        col_names = [
            tr("col_status", "Status"),
            tr("col_hostname", "Nome"),
            tr("col_ip", "IP"),
            tr("col_manufacturer", "Fabricante"),
            tr("col_mac", "Endereço MAC"),
            tr("col_ping", "Ping"),
            tr("col_comments", "Comentários"),
        ]
        name = col_names[col] if 0 <= col < len(col_names) else f"Coluna {col}"
        tpl = tr("stat_sorting_by", "Classificando por: {col} ({order})")
        self.lbl_stats.setText(tpl.format(col=name, order=order_str))

    def apply_theme(self):
        self.setStyleSheet(DARK_STYLESHEET if self.is_dark_mode else LIGHT_STYLESHEET)
        self.btn_theme.setText(tr("theme_light", "☀️ Claro") if self.is_dark_mode else tr("theme_dark", "🌙 Escuro"))
        self.oscilloscope.is_dark = self.is_dark_mode
        self.oscilloscope.update()
        if hasattr(self, "topology_widget"):
            self.topology_widget.apply_theme(self.is_dark_mode)
        self.lbl_threads.setStyleSheet(
            "color: #38bdf8; font-weight: bold; margin-left: 10px;" if self.is_dark_mode
            else "color: #164e78; font-weight: bold; margin-left: 10px;"
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
        act_refresh = menu.addAction("🔄  Recarregar Placas e Auto-detectar Rede")
        act_refresh.triggered.connect(self.refresh_network_interfaces)

        act_dialog = menu.addAction("⚙️  Gerenciar e Ver Detalhes das Placas...")
        act_dialog.triggered.connect(self.open_interface_dialog)

        # Popup menu right below the "IP" button
        btn_pos = self.btn_subnet.mapToGlobal(QPoint(0, self.btn_subnet.height() + 2))
        menu.exec_(btn_pos)

    COMMON_MASKS = [
        (24, "255.255.255.0", "254 IPs"),
        (16, "255.255.0.0", "65k IPs"),
        (20, "255.255.240.0", "4.094 IPs"),
        (21, "255.255.248.0", "2.046 IPs"),
        (22, "255.255.252.0", "1.022 IPs"),
        (23, "255.255.254.0", "510 IPs"),
        (25, "255.255.255.128", "126 IPs"),
        (26, "255.255.255.192", "62 IPs"),
        (27, "255.255.255.224", "30 IPs"),
        (28, "255.255.255.240", "14 IPs"),
        (29, "255.255.255.248", "6 IPs"),
        (30, "255.255.255.252", "2 IPs"),
        (8,  "255.0.0.0", "16M IPs"),
    ]

    def populate_mask_combo(self):
        self.combo_mask.blockSignals(True)
        self.combo_mask.clear()
        for cidr, netmask, desc in self.COMMON_MASKS:
            self.combo_mask.addItem(f"/{cidr} • {netmask} ({desc})", cidr)
        self.combo_mask.blockSignals(False)

    def set_mask_cidr(self, cidr):
        try:
            cidr_int = int(cidr)
        except (ValueError, TypeError):
            cidr_int = 24

        self.combo_mask.blockSignals(True)
        idx = -1
        for i in range(self.combo_mask.count()):
            if self.combo_mask.itemData(i) == cidr_int:
                idx = i
                break

        if idx != -1:
            self.combo_mask.setCurrentIndex(idx)
        else:
            try:
                fake_net = ipaddress.IPv4Network(f"0.0.0.0/{cidr_int}", strict=False)
                mask_str = str(fake_net.netmask)
                total_ips = max(0, fake_net.num_addresses - 2)
                self.combo_mask.addItem(f"/{cidr_int} • {mask_str} ({total_ips} IPs)", cidr_int)
                self.combo_mask.setCurrentIndex(self.combo_mask.count() - 1)
            except Exception:
                pass
        self.combo_mask.blockSignals(False)

    def auto_detect_mask_from_inputs(self):
        start_text = self.txt_start_ip.text().strip()
        end_text = self.txt_end_ip.text().strip()
        try:
            ip1 = ipaddress.IPv4Address(start_text)
            ip2 = ipaddress.IPv4Address(end_text)
            if ip1 <= ip2:
                for prefix in range(30, 7, -1):
                    net = ipaddress.IPv4Network(f"{start_text}/{prefix}", strict=False)
                    first_host = str(net.network_address + 1) if net.num_addresses > 2 else str(net.network_address)
                    last_host = str(net.broadcast_address - 1) if net.num_addresses > 2 else str(net.broadcast_address)
                    if (first_host == start_text and last_host == end_text) or \
                       (str(net.network_address) == start_text and str(net.broadcast_address) == end_text):
                        self.set_mask_cidr(prefix)
                        return
        except Exception:
            pass

    def select_network_interface(self, iface_info: dict):
        self.local_info = iface_info
        start_ip = iface_info.get("start_ip", "")
        end_ip = iface_info.get("end_ip", "")
        cidr = iface_info.get("cidr", "24")
        netmask = iface_info.get("netmask", "255.255.255.0")

        self.txt_start_ip.blockSignals(True)
        self.txt_end_ip.blockSignals(True)
        if start_ip:
            self.txt_start_ip.setText(start_ip)
        if end_ip:
            self.txt_end_ip.setText(end_ip)
        self.txt_start_ip.blockSignals(False)
        self.txt_end_ip.blockSignals(False)

        self.set_mask_cidr(cidr)

        iface_name = iface_info.get("name", "eth0")
        ip_addr = iface_info.get("ip", "")
        self.lbl_stats.setText(f"Placa selecionada: {iface_info.get('icon', '🖧')} {iface_name} ({ip_addr}/{cidr} • {netmask}) • Faixa: {start_ip} - {end_ip}")

    def refresh_network_interfaces(self):
        new_info = get_local_network_info()
        self.select_network_interface(new_info)
        QMessageBox.information(
            self,
            "Rede Atualizada",
            f"Placa de rede e máscara atualizadas com sucesso:\n\n"
            f"• Interface: {new_info.get('name')} ({new_info.get('type')})\n"
            f"• Endereço IPv4: {new_info.get('ip')}\n"
            f"• Máscara de Sub-rede: {new_info.get('netmask')} (/{new_info.get('cidr')})\n"
            f"• Faixa de IPs: {new_info.get('start_ip')} — {new_info.get('end_ip')}"
        )

    def open_interface_dialog(self):
        cur_name = self.local_info.get("name") or self.local_info.get("interface", "")
        dlg = NetworkInterfaceDialog(self, current_interface=cur_name)
        dlg.interface_selected.connect(self.select_network_interface)
        dlg.exec_()

    def apply_class_c(self):
        """Fallback helper if called programmatically."""
        self.select_network_interface(self.local_info)

    def on_mask_changed(self):
        cidr = self.combo_mask.currentData()
        if not cidr:
            return
        try:
            start_ip = self.txt_start_ip.text().strip()
            if not start_ip:
                start_ip = self.local_info.get("ip", "192.168.1.1")
            net = ipaddress.IPv4Network(f"{start_ip}/{cidr}", strict=False)
            first_host = str(net.network_address + 1) if net.num_addresses > 2 else str(net.network_address)
            last_host = str(net.broadcast_address - 1) if net.num_addresses > 2 else str(net.broadcast_address)
            self.txt_start_ip.blockSignals(True)
            self.txt_end_ip.blockSignals(True)
            self.txt_start_ip.setText(first_host)
            self.txt_end_ip.setText(last_host)
            self.txt_start_ip.blockSignals(False)
            self.txt_end_ip.blockSignals(False)
        except Exception:
            pass

    def check_and_apply_update(self):
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        
        self._update_dialog = QProgressDialog("Iniciando verificação de atualização...", "Cancelar", 0, 0, self)
        self._update_dialog.setWindowTitle("IP Scan IGT — Atualização do Sistema")
        self._update_dialog.setWindowModality(Qt.WindowModal)
        self._update_dialog.setMinimumDuration(0)
        self._update_dialog.setAutoClose(False)
        self._update_dialog.setAutoReset(False)
        self._update_dialog.setStyleSheet("QProgressDialog { padding: 15px; font-size: 13px; }")
        self._update_dialog.show()

        self._update_worker = AppUpdateWorker(repo_dir)
        self._update_worker.progress_status.connect(self.on_update_status)
        self._update_worker.update_finished.connect(self.on_update_completed)
        self._update_dialog.canceled.connect(self._update_worker.terminate)
        self._update_worker.start()

    def on_update_status(self, text: str):
        if hasattr(self, "_update_dialog") and self._update_dialog:
            self._update_dialog.setLabelText(text)

    def on_update_completed(self, success: bool, message: str, needs_restart: bool):
        if hasattr(self, "_update_dialog") and self._update_dialog:
            self._update_dialog.close()
            self._update_dialog = None

        if success:
            if needs_restart:
                reply = QMessageBox.question(
                    self,
                    "Atualização Concluída",
                    message,
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes
                )
                if reply == QMessageBox.Yes:
                    if getattr(sys, "frozen", False):
                        QProcess.startDetached(sys.executable, [])
                    else:
                        main_py = os.path.abspath(__file__)
                        QProcess.startDetached(sys.executable, [main_py])
                    QApplication.quit()
            else:
                QMessageBox.information(self, "IP Scan IGT Atualizado", message)
        else:
            QMessageBox.warning(self, "Aviso de Atualização", message)

    def toggle_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.set_scan_running_state(False)
            self.lbl_stats.setText(tr("stat_scan_stopping", "Parando varredura..."))
            return

        start_ip = self.txt_start_ip.text().strip()
        end_ip = self.txt_end_ip.text().strip()

        try:
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            if start_int > end_int:
                start_int, end_int = end_int, start_int
            if (end_int - start_int) > 65536:
                QMessageBox.warning(self, tr("range_too_large_title", "Faixa Muito Grande"), tr("range_too_large_msg", "A faixa excede 65.536 endereços IP. Por favor, especifique uma sub-rede /16 ou menor."))
                return
            ip_list = [str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)]
        except Exception as e:
            QMessageBox.warning(self, tr("range_invalid_title", "Faixa Inválida"), tr("range_invalid_msg", "Endereço IP inválido especificado: {err}").format(err=e))
            return

        self.records.clear()
        self.tree.clear()
        self.details_table.setRowCount(0)
        self.oscilloscope.clear()
        self.live_ping_worker.set_target("")
        self.lbl_panel_title.setText(tr("select_host_prompt", "● Monitor de Ping Dinâmico & Detalhes: [Selecione um dispositivo da lista]"))
        self.main_tabs.setCurrentIndex(0)  # Switch to Resultados

        self.set_scan_running_state(True, len(ip_list))

        self.scan_worker = ScanWorker(ip_list, self.local_info, enable_onvif=self.chk_onvif.isChecked(), max_workers=64)
        self.scan_worker.host_found.connect(self.on_host_found)
        self.scan_worker.progress_updated.connect(self.on_scan_progress)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def scan_favorites_only(self):
        if not self.fav_records:
            QMessageBox.information(self, tr("fav_empty_title", "Favoritos Vazios"), tr("fav_empty_msg", "Nenhum dispositivo salvo nos Favoritos para verificar."))
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
            self.btn_start.setText(f"⏹  {tr('btn_stop')}")
            self.btn_start.setObjectName("btnStop")
            self.btn_start.style().unpolish(self.btn_start)
            self.btn_start.style().polish(self.btn_start)
            self.btn_start.update()
            self.act_scan.setEnabled(False)
            self.act_stop.setEnabled(True)
            self.prog_bar.setMaximum(total)
            self.prog_bar.setValue(0)
            self.prog_bar.setVisible(True)
        else:
            self.btn_start.setText(f"▶  {tr('btn_scan')}")
            self.btn_start.setObjectName("btnStart")
            self.btn_start.style().unpolish(self.btn_start)
            self.btn_start.style().polish(self.btn_start)
            self.btn_start.update()
            self.act_scan.setEnabled(True)
            self.act_stop.setEnabled(False)
            self.prog_bar.setVisible(False)

    @pyqtSlot(int, int, str)
    def on_scan_progress(self, current: int, total: int, current_ip: str):
        self.prog_bar.setValue(current)
        self.lbl_stats.setText(tr("stat_scan_checking", "Verificando: {ip} ({curr}/{total})...").format(ip=current_ip, curr=current, total=total))

    def inspect_record_guard(self, rec: HostRecord):
        gw_ip = self.local_info.get("gateway", "")
        alerts = NETWORK_GUARD.inspect_host(
            ip=rec.ip,
            mac=rec.mac,
            hostname=rec.hostname,
            vendor=rec.vendor,
            gateway_ip=gw_ip,
        )
        rec.guard_alerts = alerts
        if alerts:
            rec.guard_badge = " ".join(a.badge_text() for a in alerts[:2])
            for a in alerts:
                if a.severity in ("CRITICAL", "HIGH") and self.watchdog_cfg.get("notify_desktop", True):
                    send_desktop_notification(
                        title=f"🚨 Network Guard: {a.alert_type} ({rec.ip})",
                        message=a.details,
                        is_critical=(a.severity == "CRITICAL"),
                        tray_icon=getattr(self, "tray_icon", None),
                    )
        else:
            rec.guard_badge = ""

    @pyqtSlot(object)
    def on_host_found(self, rec: HostRecord):
        self.inspect_record_guard(rec)
        self.records[rec.ip] = rec
        self.add_or_update_tree_node(self.tree, rec)
        self.update_status_stats()

    def on_fav_host_found(self, rec: HostRecord):
        self.inspect_record_guard(rec)
        self.fav_records[rec.ip] = rec
        self.add_or_update_tree_node(self.fav_tree, rec)
        self.update_status_stats()

    @pyqtSlot(int, float)
    def on_scan_finished(self, found_count: int, elapsed_sec: float):
        self.set_scan_running_state(False)
        self.lbl_stats.setText(tr("stat_scan_finished", "Concluído em {sec:.1f}s • {count} dispositivo(s) online encontrado(s)").format(sec=elapsed_sec, count=found_count))
        col = self.tree.sortColumn()
        order = self.tree.header().sortIndicatorOrder()
        self.tree.sortItems(col if col >= 0 else 2, order)
        self.update_status_stats()
        if hasattr(self, "topology_widget"):
            self.topology_widget.set_network_data(self.records, self.local_info)

    def add_or_update_tree_node(self, target_tree: QTreeWidget, rec: HostRecord):
        correlate_host_vulnerabilities(rec)
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

        # Col 0: Status Orb (Green circle for online, muted circle for offline)
        parent_item.setText(0, "●" if rec.alive else "○")
        parent_item.setTextAlignment(0, Qt.AlignCenter)
        orb_col = QColor("#10b981") if rec.alive else (QColor("#64748b") if self.is_dark_mode else QColor("#7c8794"))
        parent_item.setForeground(0, orb_col)
        font_status = QFont("Segoe UI", 9, QFont.Bold)
        parent_item.setFont(0, font_status)

        # Col 1: Nome (Hostname or device type)
        display_name = rec.hostname or f"Host [{rec.ip}]"
        parent_item.setText(1, display_name)

        # Col 2: IP
        parent_item.setText(2, rec.ip)

        # Col 3: Fabricante
        parent_item.setText(3, rec.vendor or tr("unknown", "Desconhecido"))

        # Col 4: MAC
        parent_item.setText(4, rec.mac or tr("not_available", "N/D"))

        # Col 5: Ping
        parent_item.setText(5, rec.format_ping())
        if rec.rtt_ms >= 0:
            if rec.rtt_ms < 2.0:
                parent_item.setForeground(5, QColor("#10b981") if self.is_dark_mode else QColor("#059669"))
            elif rec.rtt_ms < 25.0:
                parent_item.setForeground(5, QColor("#38bdf8") if self.is_dark_mode else QColor("#0284c7"))
            else:
                parent_item.setForeground(5, QColor("#fbbf24") if self.is_dark_mode else QColor("#d97706"))

        # Col 6: Comentários / Serviços / SNMP / UPnP / CVEs / Network Guard
        comment_parts = []
        if rec.guard_badge:
            comment_parts.append(rec.guard_badge)
        if rec.risk_badge:
            comment_parts.append(rec.risk_badge)
        if rec.device_type and rec.device_type != tr("dev_host_online", "🖧 Host Online"):
            comment_parts.append(rec.device_type)
        if rec.snmp_info:
            comment_parts.append(f"SNMP: {rec.snmp_info}")
        if rec.upnp_info:
            comment_parts.append(f"UPnP: {rec.upnp_info}")
        if rec.http_info:
            comment_parts.append(rec.http_info)
        elif rec.ssl_info:
            comment_parts.append(f"SSL: {rec.ssl_info}")
        elif rec.ssh_banner:
            comment_parts.append(rec.ssh_banner)
        if rec.open_ports:
            comment_parts.append(f"{tr('ports_label', 'Portas')}: {rec.format_ports()}")

        parent_item.setText(6, " • ".join(comment_parts) if comment_parts else tr("no_services_found", "Nenhum serviço identificado"))
        if rec.risk_level in ("CRITICAL", "HIGH") or "[🚨" in (rec.guard_badge or ""):
            parent_item.setForeground(6, QColor("#f87171") if self.is_dark_mode else QColor("#dc2626"))
        else:
            parent_item.setForeground(6, QColor("#cbd5e1") if self.is_dark_mode else QColor("#1e293b"))

        # Sub-items [ + ] for individual services (HTTP, HTTPS, SMB, SNMP, CVEs, etc.)
        parent_item.takeChildren()
        link_color = QColor("#0969da") if not self.is_dark_mode else QColor("#38bdf8")
        text_color = QColor("#475569") if not self.is_dark_mode else QColor("#cbd5e1")

        rec.resources = build_resources_for_host(rec)
        for res in rec.resources:
            child = QTreeWidgetItem(parent_item)
            child.setText(1, f"    {res.icon}  {res.title}")
            child.setText(2, res.url or "")
            child.setText(6, res.detail)
            child.setData(2, Qt.UserRole, rec.ip)
            child.setData(1, Qt.UserRole, res.url)
            if res.icon in ("🚨", "⚠️"):
                child.setForeground(1, QColor("#f87171") if self.is_dark_mode else QColor("#dc2626"))
            else:
                child.setForeground(1, link_color if res.url else text_color)
            if res.url:
                child.setForeground(2, link_color)

        # Keep collapsed by default for clean and uncluttered UI/UX
        parent_item.setExpanded(False)

        if target_tree == self.tree and hasattr(self, "topology_widget") and (not self.scan_worker or not self.scan_worker.isRunning()):
            self.topology_widget.set_network_data(self.records, self.local_info)

    def sort_tree_by_ip(self, target_tree: QTreeWidget):
        col = target_tree.sortColumn()
        order = target_tree.header().sortIndicatorOrder()
        target_tree.sortItems(col if col >= 0 else 2, order)

    def update_status_stats(self):
        tree = self.get_active_tree()
        online_count = tree.topLevelItemCount()
        records_pool = self.records if self.main_tabs.currentIndex() != 1 else self.fav_records

        services_count = sum(1 for r in records_pool.values() if r.open_ports)
        cve_count = sum(len(getattr(r, "vulnerabilities", []) or []) for r in records_pool.values())
        rtts = [r.rtt_ms for r in records_pool.values() if r.rtt_ms >= 0]
        avg_rtt = f"{sum(rtts)/len(rtts):.2f} ms" if rtts else "-- ms"

        summary_template = tr("stat_results_summary", "Resultados: {online} dispositivo(s) online  |  {services} com serviços  |  Latência média: {avg}")
        self.lbl_stats.setText(summary_template.format(online=online_count, services=services_count, avg=avg_rtt))
        if hasattr(self, "kpi_online"):
            tpl = tr("kpi_online", "● {count} Online")
            self.kpi_online.setText(tpl.format(count=online_count))
        if hasattr(self, "kpi_latency"):
            self.kpi_latency.setText(f"⚡ {avg_rtt}")
        if hasattr(self, "kpi_services"):
            tpl = tr("kpi_services", "🛡️ {count} Serviços")
            self.kpi_services.setText(tpl.format(count=services_count))
        if hasattr(self, "kpi_cves"):
            tpl = tr("kpi_cves", "⚠️ {count} CVEs")
            self.kpi_cves.setText(tpl.format(count=cve_count))

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
        self.lbl_panel_title.setText(f"● {tr('details_header', 'Monitor de Ping Dinâmico & Detalhes')}: {rec.ip} — {rec.hostname or tr('dev_network_dev', 'Dispositivo')}")
        self.oscilloscope.clear(ip)
        self.live_ping_worker.set_target(ip)
        self.populate_details_table(rec)

    def populate_details_table(self, rec: HostRecord):
        ttl_detail = tr("direct_lan", "Rede Local Direta") if rec.ttl in [64, 128, 255] else tr("hops_detected", "Saltos detectados")
        na = tr("not_available", "N/D")
        props = [
            (tr("prop_ip", "Endereço IP"), rec.ip),
            (tr("prop_hostname", "Nome / Hostname"), rec.hostname or tr("not_configured", "Não configurado")),
            (tr("prop_type_sys", "Tipo / Sistema"), f"{rec.device_type} • {rec.os_family}"),
            (tr("prop_vendor", "Fabricante (OUI)"), rec.vendor or tr("not_identified", "Não identificado")),
            (tr("prop_mac", "Endereço MAC"), rec.mac or na),
            (tr("prop_latency", "Latência (Ping)"), f"{rec.format_ping()} ({tr('method_label', 'Método')}: {rec.ping_method})"),
            (tr("prop_ttl", "TTL de Rede"), f"{rec.ttl} ({ttl_detail})" if rec.ttl > 0 else na),
            (tr("prop_open_ports", "Portas TCP Abertas"), rec.format_ports() or tr("no_default_ports", "Nenhuma porta padrão aberta")),
            (tr("prop_http", "HTTP / Servidor Web"), rec.http_info or tr("none", "Nenhum")),
            (tr("prop_ssl", "Certificado SSL / HTTPS"), f"CN={rec.ssl_info}" if rec.ssl_info else tr("none", "Nenhum")),
            (tr("prop_ssh", "Banner SSH (Porta 22)"), rec.ssh_banner or tr("closed", "Fechada")),
            (tr("prop_netbios", "NetBIOS / Grupo SMB"), rec.netbios_domain or na),
        ]

        if rec.snmp_info:
            props.append((tr("prop_snmp", "Auditoria SNMP (UDP 161)"), rec.snmp_info))
        if rec.upnp_info:
            props.append((tr("prop_upnp", "Descoberta UPnP / SSDP (UDP 1900)"), rec.upnp_info))
        if rec.vulnerabilities:
            cve_str = " | ".join(f"{v.cve_id} ({v.severity} CVSS {v.cvss:.1f}: {v.title})" for v in rec.vulnerabilities)
            props.append((tr("prop_cves", "Vulnerabilidades (CVEs)"), cve_str))
        if rec.guard_alerts:
            g_str = " | ".join(f"{getattr(a, 'alert_type', '')}: {getattr(a, 'details', '')}" for a in rec.guard_alerts)
            props.append((tr("prop_guard", "Network Guard (Segurança L2)"), g_str))
        if rec.onvif_url or rec.onvif_model:
            props.append((tr("prop_onvif", "ONVIF Câmera / NVR"), f"{rec.onvif_model} ({rec.onvif_url})"))
        if rec.rtsp_url or 554 in rec.open_ports:
            props.append((tr("prop_rtsp", "Stream RTSP de Vídeo"), rec.rtsp_url or f"rtsp://{rec.ip}:554/"))
        if rec.nmap_services:
            svc_str = "; ".join(f"{p}: {s}" for p, s in rec.nmap_services.items())
            props.append((tr("prop_nmap_audited", "Serviços Auditados (Nmap)"), svc_str))

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
            elif url.startswith("rdp://"):
                self.open_rdp_connection(ip or url.replace("rdp://", ""))
            elif url.startswith("ssh://"):
                self.open_ssh_connection(ip or url.replace("ssh://", ""))
            elif url.startswith("smb://"):
                open_smb(ip or url.replace("smb://", "").strip("/"))
            else:
                QDesktopServices.openUrl(QUrl(url))
            return
        records_pool = self.records if ip in self.records else self.fav_records
        if ip and ip in records_pool:
            rec = records_pool[ip]
            if rec.rtsp_url or 554 in rec.open_ports:
                self.launch_rtsp_stream(rec.rtsp_url or f"rtsp://{ip}:554/", ip=ip)
            elif 3389 in rec.open_ports:
                self.open_rdp_connection(ip)
            elif 22 in rec.open_ports:
                self.open_ssh_connection(ip)
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
        a_add_fav = menu.addAction(f"★ {tr('ctx_add_fav')}")
        menu.addSeparator()

        a_rtsp = None
        a_cam_cfg = None
        if rec.rtsp_url or 554 in rec.open_ports:
            a_rtsp = menu.addAction(f"🎬 {tr('ctx_rtsp')}")
            a_cam_cfg = menu.addAction(tr("config_video"))

        a_onvif = None
        if rec.onvif_url:
            a_onvif = menu.addAction(f"🎥 {tr('col_cameras')}")

        a_nmap = menu.addAction(f"🔍 {tr('ctx_nmap')}")
        a_traceroute = menu.addAction(f"🧭 {tr('ctx_traceroute', 'Traceroute Visual (Rota TTL)...')}")
        a_trust_mac = None
        if rec.mac and rec.mac != "N/D":
            a_trust_mac = menu.addAction(f"🛡️ {tr('ctx_trust_mac', 'Marcar MAC como Confiável (Network Guard)')}")
        menu.addSeparator()

        a_rdp = menu.addAction(f"🖥️ {tr('ctx_rdp')}")
        a_ssh = menu.addAction(f"💻 {tr('ctx_ssh')}")
        a_wol = menu.addAction(f"⚡ {tr('ctx_wol')}")
        menu.addSeparator()

        a_open_http = menu.addAction(tr("ctx_open_http"))
        a_open_https = menu.addAction(tr("ctx_open_https"))
        a_open_smb = menu.addAction(tr("ctx_open_smb"))
        menu.addSeparator()

        a_copy_ip = menu.addAction(tr("ctx_copy_ip"))
        a_copy_mac = menu.addAction(tr("ctx_copy_mac"))
        a_copy_all = menu.addAction(tr("export_txt"))
        menu.addSeparator()

        a_term_ping = menu.addAction(tr("ctx_ping"))

        action = menu.exec_(self.tree.viewport().mapToGlobal(pos))
        if action == a_add_fav:
            self.add_record_to_favorites(rec)
        elif a_rtsp and action == a_rtsp:
            self.launch_rtsp_stream(rec.rtsp_url or f"rtsp://{rec.ip}:554/", ip=rec.ip)
        elif a_cam_cfg and action == a_cam_cfg:
            self.open_camera_config_dialog()
        elif a_onvif and action == a_onvif:
            QDesktopServices.openUrl(QUrl(rec.onvif_url))
        elif action == a_nmap:
            self.open_nmap_dialog(rec.ip, rec.hostname)
        elif action == a_traceroute:
            self.open_traceroute_dialog(rec.ip)
        elif a_trust_mac and action == a_trust_mac:
            NETWORK_GUARD.trust_mac(rec.mac, trusted=True, ip=rec.ip, hostname=rec.hostname, vendor=rec.vendor)
            rec.guard_alerts = []
            rec.guard_badge = ""
            self.add_or_update_tree_node(self.tree, rec)
            self.lbl_stats.setText(f"🛡️ MAC {rec.mac} ({rec.ip}) marcado como Confiável no Network Guard.")
        elif action == a_rdp:
            self.open_rdp_connection(rec.ip)
        elif action == a_ssh:
            self.open_ssh_connection(rec.ip)
        elif action == a_wol:
            self.action_send_wol(rec)
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
        a_remove = menu.addAction(f"★ {tr('ctx_remove_fav')}")
        menu.addSeparator()
        a_rtsp = None
        a_cam_cfg = None
        if rec.rtsp_url or 554 in rec.open_ports:
            a_rtsp = menu.addAction(f"🎬 {tr('ctx_rtsp')}")
            a_cam_cfg = menu.addAction(tr("config_video"))
        a_nmap = menu.addAction(f"🔍 {tr('ctx_nmap')}")
        menu.addSeparator()
        a_rdp = menu.addAction(f"🖥️ {tr('ctx_rdp')}")
        a_ssh = menu.addAction(f"💻 {tr('ctx_ssh')}")
        a_wol = menu.addAction(f"⚡ {tr('ctx_wol')}")
        menu.addSeparator()
        a_open_http = menu.addAction(tr("ctx_open_http"))
        a_open_smb = menu.addAction(tr("ctx_open_smb"))
        a_term_ping = menu.addAction(tr("ctx_ping"))
        a_copy_ip = menu.addAction(tr("ctx_copy_ip"))

        action = menu.exec_(self.fav_tree.viewport().mapToGlobal(pos))
        if action == a_remove:
            self.remove_favorite_ip(rec.ip)
        elif a_rtsp and action == a_rtsp:
            self.launch_rtsp_stream(rec.rtsp_url or f"rtsp://{rec.ip}:554/", ip=rec.ip)
        elif a_cam_cfg and action == a_cam_cfg:
            self.open_camera_config_dialog()
        elif action == a_nmap:
            self.open_nmap_dialog(rec.ip, rec.hostname)
        elif action == a_rdp:
            self.open_rdp_connection(rec.ip)
        elif action == a_ssh:
            self.open_ssh_connection(rec.ip)
        elif action == a_wol:
            self.action_send_wol(rec)
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
            QMessageBox.information(self, tr("tab_favorites"), "Selecione um dispositivo da lista de Resultados primeiro.")
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
        self.sync_watchdog_state()
        self.lbl_stats.setText(tr("stat_fav_added", "Dispositivo {ip} ({host}) adicionado aos Favoritos.").format(ip=rec.ip, host=rec.hostname or rec.ip))

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
            self.sync_watchdog_state()
            self.lbl_stats.setText(tr("stat_fav_removed", "Dispositivo {ip} removido dos Favoritos.").format(ip=ip))

    def clear_all_favorites(self):
        if not self.fav_records:
            return
        res = QMessageBox.question(self, tr("clear_fav_confirm_title", "Limpar Favoritos"), tr("clear_fav_confirm_msg", "Deseja remover todos os dispositivos salvos dos Favoritos?"), QMessageBox.Yes | QMessageBox.No)
        if res == QMessageBox.Yes:
            self.fav_records.clear()
            self.fav_tree.clear()
            self.save_favorites_to_disk()
            self.sync_watchdog_state()

    def init_system_tray(self):
        try:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            icon_path = get_resource_path("icon.ico") if IS_WINDOWS else get_resource_path("icon.png")
            if not os.path.exists(icon_path):
                icon_path = get_resource_path("icon.png")
            self.tray_icon = QSystemTrayIcon(self)
            if os.path.exists(icon_path):
                self.tray_icon.setIcon(QIcon(icon_path))
            self.tray_icon.setToolTip(f"IP Scan IGT — {get_short_version()}")

            tray_menu = QMenu(self)
            act_show = tray_menu.addAction("🖧 Abrir IP Scan IGT")
            act_show.triggered.connect(self.restore_from_tray)
            act_wd = tray_menu.addAction("🛡️ Configurar Watchdog...")
            act_wd.triggered.connect(self.open_watchdog_dialog)
            tray_menu.addSeparator()
            act_quit = tray_menu.addAction("✕ Sair Completamente")
            act_quit.triggered.connect(self.force_quit_app)
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.activated.connect(self.on_tray_activated)
            self.tray_icon.show()
        except Exception:
            self.tray_icon = None

    def on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.restore_from_tray()

    def restore_from_tray(self):
        self.showNormal()
        self.showMaximized()
        self.raise_()
        self.activateWindow()

    def force_quit_app(self):
        self._force_quit = True
        self.close()

    def sync_watchdog_state(self):
        enabled = bool(self.watchdog_cfg.get("enabled", False))
        fav_map = {ip: (rec.hostname or ip) for ip, rec in self.fav_records.items()}
        initial_states = {ip: bool(rec.alive) for ip, rec in self.fav_records.items()}
        self.watchdog_worker.update_settings(
            self.watchdog_cfg.get("interval_sec", 15),
            self.watchdog_cfg.get("failure_threshold", 2),
        )
        self.watchdog_worker.set_targets(fav_map, initial_states)

        if hasattr(self, "btn_fav_watchdog"):
            self.btn_fav_watchdog.blockSignals(True)
            self.btn_fav_watchdog.setChecked(enabled)
            if enabled:
                self.btn_fav_watchdog.setText(f"🛡️ Watchdog: ATIVO ({len(fav_map)} alvos)")
                self.btn_fav_watchdog.setStyleSheet(
                    "QPushButton { background-color: #16a34a; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 2px 10px; }"
                )
            else:
                self.btn_fav_watchdog.setText("🛡️ Watchdog Contínuo: OFF")
                self.btn_fav_watchdog.setStyleSheet("")
            self.btn_fav_watchdog.blockSignals(False)

        if enabled:
            if not self.watchdog_worker.isRunning():
                self.watchdog_worker.start()
        else:
            if self.watchdog_worker.isRunning():
                self.watchdog_worker.stop()
                self.watchdog_worker.wait(500)

    def toggle_watchdog_quick(self, checked: bool):
        self.watchdog_cfg["enabled"] = bool(checked)
        save_watchdog_config(self.watchdog_cfg)
        self.sync_watchdog_state()
        state_str = "ATIVADO" if checked else "DESATIVADO"
        self.lbl_stats.setText(f"🛡️ Monitoramento Contínuo (Watchdog) {state_str} para os dispositivos em Favoritos.")

    def open_watchdog_dialog(self):
        dlg = WatchdogDialog(self, is_dark=self.is_dark_mode)
        dlg.config_Updated.connect(self.on_watchdog_config_updated)
        dlg.trigger_manual_check.connect(self.watchdog_worker.run_single_cycle)
        dlg.exec_()

    def on_watchdog_config_updated(self, new_cfg: dict):
        self.watchdog_cfg = dict(new_cfg)
        self.sync_watchdog_state()

    @pyqtSlot(str, bool, float, int)
    def on_watchdog_host_checked(self, ip: str, alive: bool, rtt: float, fail_streak: int):
        if ip in self.fav_records:
            rec = self.fav_records[ip]
            threshold = int(self.watchdog_cfg.get("failure_threshold", 2))
            if alive:
                rec.alive = True
                rec.rtt_ms = rtt
            elif fail_streak >= threshold:
                rec.alive = False
                rec.rtt_ms = -1.0
            self.add_or_update_tree_node(self.fav_tree, rec)

    @pyqtSlot(str, str, bool, float, str)
    def on_watchdog_state_changed(self, ip: str, hostname: str, is_online: bool, rtt: float, timestamp: str):
        ev_type = "UP" if is_online else "DOWN"
        if is_online:
            details = f"Ativo recuperado e respondendo ao ping ({rtt:.2f} ms)."
            title = f"🟢 Ativo Recuperado: {hostname} ({ip})"
        else:
            details = f"Servidor crítico parou de responder após {self.watchdog_cfg.get('failure_threshold', 2)} tentativas consecutivas."
            title = f"🔴 ALERTA DE QUEDA: {hostname} ({ip})"

        ev = WatchdogEvent(
            timestamp=timestamp,
            ip=ip,
            hostname=hostname,
            event_type=ev_type,
            details=details,
            rtt_ms=rtt,
        )
        append_watchdog_event(ev)
        self.lbl_stats.setText(f"{title} — {details}")

        if self.watchdog_cfg.get("notify_desktop", True):
            send_desktop_notification(
                title=title,
                message=details,
                is_critical=not is_online,
                tray_icon=self.tray_icon,
            )

    @pyqtSlot(int, int, str)
    def on_watchdog_cycle_finished(self, online_count: int, offline_count: int, timestamp: str):
        if self.main_tabs.currentIndex() == 1:
            self.lbl_stats.setText(
                f"🛡️ Watchdog [{timestamp}]: {online_count} Favorito(s) Online • {offline_count} Offline"
            )

    def on_topology_host_selected(self, ip: str):
        rec = self.records.get(ip) or self.fav_records.get(ip)
        if not rec:
            return
        self.lbl_panel_title.setText(
            f"● {tr('details_header', 'Monitor de Ping Dinâmico & Detalhes')}: {rec.ip} — {rec.hostname or tr('dev_network_dev', 'Dispositivo')}"
        )
        self.oscilloscope.clear(ip)
        self.live_ping_worker.set_target(ip)
        self.populate_details_table(rec)

    def on_topology_host_double_clicked(self, ip: str):
        rec = self.records.get(ip) or self.fav_records.get(ip)
        if not rec:
            return
        if rec.rtsp_url or 554 in rec.open_ports:
            self.launch_rtsp_stream(rec.rtsp_url or f"rtsp://{ip}:554/", ip=ip)
        elif 80 in rec.open_ports:
            QDesktopServices.openUrl(QUrl(f"http://{ip}/"))
        elif 443 in rec.open_ports:
            QDesktopServices.openUrl(QUrl(f"https://{ip}/"))
        elif 22 in rec.open_ports:
            self.open_ssh_connection(ip)
        elif 3389 in rec.open_ports:
            self.open_rdp_connection(ip)
        else:
            self.open_nmap_dialog(ip, rec.hostname)

    def on_topology_host_context_menu(self, ip: str, global_pos: QPoint):
        rec = self.records.get(ip) or self.fav_records.get(ip)
        if not rec:
            return
        menu = QMenu(self)
        a_fav = menu.addAction(f"★ {tr('ctx_add_fav')}")
        a_nmap = menu.addAction(f"🔍 {tr('ctx_nmap')}")
        menu.addSeparator()
        a_http = menu.addAction(tr("ctx_open_http"))
        a_https = menu.addAction(tr("ctx_open_https"))
        a_ssh = menu.addAction(f"💻 {tr('ctx_ssh')}")
        a_rdp = menu.addAction(f"🖥️ {tr('ctx_rdp')}")
        a_ping = menu.addAction(tr("ctx_ping"))
        action = menu.exec_(global_pos)
        if action == a_fav:
            self.add_record_to_favorites(rec)
        elif action == a_nmap:
            self.open_nmap_dialog(rec.ip, rec.hostname)
        elif action == a_http:
            QDesktopServices.openUrl(QUrl(f"http://{rec.ip}/"))
        elif action == a_https:
            QDesktopServices.openUrl(QUrl(f"https://{rec.ip}/"))
        elif action == a_ssh:
            self.open_ssh_connection(rec.ip)
        elif action == a_rdp:
            self.open_rdp_connection(rec.ip)
        elif action == a_ping:
            open_terminal_ping(rec.ip)

    def action_open_http(self):
        ip = self.oscilloscope.current_ip
        if ip:
            QDesktopServices.openUrl(QUrl(f"http://{ip}/"))

    def action_open_https(self):
        ip = self.oscilloscope.current_ip
        if ip:
            QDesktopServices.openUrl(QUrl(f"https://{ip}/"))

    def action_open_smb(self):
        ip = self.get_selected_or_current_ip()
        if ip:
            open_smb(ip)

    def get_selected_or_current_ip(self) -> str:
        ip = self.oscilloscope.current_ip
        if not ip:
            tree = self.get_active_tree()
            items = tree.selectedItems()
            if items:
                ip = items[0].data(2, Qt.UserRole) or ""
        return ip

    def open_rdp_connection(self, ip: str):
        if not ip:
            QMessageBox.information(self, "RDP", "Selecione um dispositivo na lista primeiro.")
            return
        ok = open_rdp(ip)
        if ok:
            self.lbl_stats.setText(f"Iniciando conexão RDP para {ip}...")
        else:
            QMessageBox.warning(
                self,
                "Cliente RDP Ausente",
                f"Nenhum cliente RDP foi encontrado no sistema para conectar em {ip}.\n\n"
                f"No Linux, instale o Remmina para acesso à Área de Trabalho Remota:\n"
                f"sudo apt install remmina"
            )

    def open_ssh_connection(self, ip: str):
        if not ip:
            QMessageBox.information(self, "SSH", "Selecione um dispositivo na lista primeiro.")
            return
        rec = self.records.get(ip) or self.fav_records.get(ip)
        hostname = rec.hostname if rec else ""
        dlg = SshConnectDialog(self, ip=ip, hostname=hostname)
        if dlg.exec_() == QDialog.Accepted:
            ok = open_terminal_ssh(ip, user=dlg.user, password=dlg.password, port=dlg.port)
            if ok:
                user_prefix = f"{dlg.user}@" if dlg.user else ""
                port_suffix = f":{dlg.port}" if dlg.port != 22 else ""
                self.lbl_stats.setText(f"Iniciando sessão SSH para {user_prefix}{ip}{port_suffix}...")
            else:
                QMessageBox.warning(
                    self,
                    "Terminal Ausente",
                    f"Não foi possível abrir o emulador de terminal para conectar em {ip}."
                )

    def open_camera_config_dialog(self):
        dlg = VideoConfigDialog(self)
        dlg.exec_()

    def open_system_doctor_dialog(self):
        from system_doctor_dialog import SystemDoctorDialog
        dlg = SystemDoctorDialog(self, is_dark=self.is_dark_mode)
        dlg.exec_()

    def open_internet_test_dialog(self):
        from internet_test_dialog import InternetQualityDialog
        gw = self.local_info.get("gateway", "")
        dlg = InternetQualityDialog(self, gateway_ip=gw, is_dark=self.is_dark_mode)
        dlg.showMaximized()
        dlg.exec_()

    def action_open_rdp(self):
        ip = self.get_selected_or_current_ip()
        self.open_rdp_connection(ip)

    def action_open_ssh(self):
        ip = self.get_selected_or_current_ip()
        self.open_ssh_connection(ip)

    def action_open_wol(self):
        ip = self.get_selected_or_current_ip()
        if not ip:
            QMessageBox.information(self, "Wake-on-LAN", "Selecione um dispositivo na lista primeiro.")
            return
        rec = self.records.get(ip) or self.fav_records.get(ip)
        if rec:
            self.action_send_wol(rec)

    def action_send_wol(self, rec: HostRecord):
        if not rec.mac or rec.mac == "N/D":
            QMessageBox.warning(
                self,
                "Wake-on-LAN",
                f"O dispositivo {rec.ip} não possui endereço MAC identificado.\n"
                f"O Wake-on-LAN exige o endereço MAC físico da placa para enviar o Magic Packet."
            )
            return
        bcast = self.local_info.get("broadcast", "255.255.255.255")
        ok = send_wake_on_lan(rec.mac, broadcast_ip=bcast)
        if ok:
            self.lbl_stats.setText(f"⚡ Magic Packet Wake-on-LAN enviado para {rec.mac} ({rec.ip})!")
            QMessageBox.information(
                self,
                "Wake-on-LAN Enviado",
                f"Magic Packet Wake-on-LAN enviado com sucesso!\n\n"
                f"• Host: {rec.hostname or rec.ip}\n"
                f"• Endereço MAC: {rec.mac}\n"
                f"• Broadcast: {bcast}:9\n\n"
                f"Se o recurso Wake-on-LAN estiver ativado na BIOS/placa de rede do dispositivo, ele será iniciado."
            )
        else:
            QMessageBox.critical(self, "Erro WoL", f"Falha ao enviar pacote Wake-on-LAN para o MAC {rec.mac}.")

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

    def open_network_guard_dialog(self):
        gw = self.local_info.get("gateway", "")
        dlg = NetworkGuardDialog(self, records=self.records, gateway_ip=gw, is_dark=self.is_dark_mode)
        dlg.guard_updated.connect(self.on_guard_updated)
        dlg.exec_()

    def on_guard_updated(self):
        for rec in self.records.values():
            self.add_or_update_tree_node(self.tree, rec)
        self.update_status_stats()

    def open_snapshot_diff_dialog(self):
        iface_str = f"{self.local_info.get('name', 'eth0')} ({self.local_info.get('ip', '')}/{self.local_info.get('cidr', '24')})"
        dlg = SnapshotDiffDialog(
            self,
            current_records=self.records,
            interface_str=iface_str,
            is_dark=self.is_dark_mode,
        )
        dlg.exec_()

    def action_open_traceroute(self):
        target = self.get_selected_or_current_ip() or self.local_info.get("gateway", "") or self.txt_start_ip.text().strip()
        self.open_traceroute_dialog(target)

    def open_traceroute_dialog(self, target_ip: str = ""):
        dlg = TracerouteDialog(
            self,
            target_ip=target_ip,
            known_records=self.records,
            local_ip=self.local_info.get("ip", ""),
            gateway_ip=self.local_info.get("gateway", ""),
            is_dark=self.is_dark_mode,
        )
        dlg.exec_()

    def generate_executive_html_report(self, records: dict) -> str:
        rec_list = list(records.values())
        for r in rec_list:
            correlate_host_vulnerabilities(r)

        total = len(rec_list)
        online = sum(1 for r in rec_list if r.alive)
        offline = total - online
        onvif_count = sum(1 for r in rec_list if r.onvif_url or 554 in r.open_ports or 8899 in r.open_ports)
        snmp_upnp_count = sum(1 for r in rec_list if r.snmp_info or r.upnp_info)

        all_cves = []
        crit_count = 0
        high_count = 0
        med_count = 0
        for r in rec_list:
            for v in (getattr(r, "vulnerabilities", []) or []):
                all_cves.append((r, v))
                if v.severity == "CRITICAL":
                    crit_count += 1
                elif v.severity == "HIGH":
                    high_count += 1
                else:
                    med_count += 1

        # Cálculo do Score de Segurança da Rede (0 - 100)
        penalty = (crit_count * 18) + (high_count * 9) + (med_count * 4)
        security_score = max(0, min(100, 100 - penalty))
        if security_score >= 90:
            sec_grade, sec_color = "A (Excelente)", "#059669"
        elif security_score >= 75:
            sec_grade, sec_color = "B (Bom)", "#0284c7"
        elif security_score >= 55:
            sec_grade, sec_color = "C (Atenção)", "#d97706"
        else:
            sec_grade, sec_color = "D/F (Crítico)", "#dc2626"

        vendors = {}
        for r in rec_list:
            v = r.vendor or "Desconhecido"
            vendors[v] = vendors.get(v, 0) + 1
        top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:5]
        top_vendors_html = " • ".join(f"<b>{v}</b> ({c})" for v, c in top_vendors) if top_vendors else "Nenhum"

        now_str = time.strftime("%d/%m/%Y às %H:%M:%S")
        iface_str = f"{self.local_info.get('name', 'eth0')} ({self.local_info.get('ip', '')}/{self.local_info.get('cidr', '24')})"
        full_ver = get_full_version()

        # Renderiza o Mapa de Topologia em Base64 PNG para embutir no HTML/PDF
        topo_b64 = ""
        if hasattr(self, "topology_widget") and self.topology_widget:
            try:
                self.topology_widget.set_network_data(records, self.local_info)
                topo_b64 = self.topology_widget.render_to_base64_png()
            except Exception:
                topo_b64 = ""

        topo_section_html = ""
        if topo_b64:
            topo_section_html = f"""
            <h2 style="font-size:17px; color:#0f172a; border-left:4px solid #0969da; padding-left:10px; margin:28px 0 12px 0;">
                🗺️ Mapa Visual de Topologia da Rede (NOC)
            </h2>
            <div style="text-align:center; background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:14px; margin-bottom:24px;">
                <img src="data:image/png;base64,{topo_b64}" alt="Topologia da Rede" style="max-width:100%; height:auto; border-radius:6px;" />
            </div>
            """

        # Matriz de Vulnerabilidades (CVEs)
        cve_section_html = ""
        if all_cves:
            cve_rows = []
            for r, v in all_cves:
                sev_bg = "#fee2e2" if v.severity == "CRITICAL" else ("#ffedd5" if v.severity == "HIGH" else "#fef9c3")
                sev_fg = "#991b1b" if v.severity == "CRITICAL" else ("#9a3412" if v.severity == "HIGH" else "#854d0e")
                cve_rows.append(f"""
                <tr style="border-bottom: 1px solid #f1f5f9;">
                    <td style="padding:8px 10px; font-family:monospace; font-weight:bold; color:#0969da;">{r.ip} ({r.hostname or '--'})</td>
                    <td style="padding:8px 10px; font-weight:bold;">{v.cve_id}</td>
                    <td style="padding:8px 10px;"><span style="background:{sev_bg}; color:{sev_fg}; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:11px;">{v.severity} (CVSS {v.cvss:.1f})</span></td>
                    <td style="padding:8px 10px;"><b>{v.title}</b><br><span style="color:#64748b; font-size:12px;">{v.description}</span></td>
                    <td style="padding:8px 10px; color:#059669; font-size:12px;">{v.remediation}</td>
                </tr>
                """)
            cve_section_html = f"""
            <h2 style="font-size:17px; color:#991b1b; border-left:4px solid #dc2626; padding-left:10px; margin:28px 0 12px 0;">
                ⚠️ Matriz de Vulnerabilidades e Riscos Detectados ({len(all_cves)} CVEs)
            </h2>
            <table style="margin-bottom:24px;">
                <thead>
                    <tr>
                        <th>Host Afetado</th>
                        <th>Código CVE</th>
                        <th>Severidade / CVSS</th>
                        <th>Vulnerabilidade</th>
                        <th>Recomendação de Mitigação</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(cve_rows)}
                </tbody>
            </table>
            """

        # Seção de Infraestrutura SNMP, Impressoras e UPnP
        infra_rows = []
        for r in rec_list:
            if r.snmp_info or r.upnp_info:
                telemetry = " • ".join(x for x in [
                    f"<b>SNMP:</b> {r.snmp_info}" if r.snmp_info else "",
                    f"<b>UPnP:</b> {r.upnp_info}" if r.upnp_info else "",
                ] if x)
                infra_rows.append(f"""
                <tr style="border-bottom: 1px solid #f1f5f9;">
                    <td style="padding:8px 10px; font-family:monospace; font-weight:bold; color:#0969da;">{r.ip}</td>
                    <td style="padding:8px 10px; font-weight:600;">{r.hostname or '--'}</td>
                    <td style="padding:8px 10px;">{r.device_type or '--'}</td>
                    <td style="padding:8px 10px;">{telemetry}</td>
                </tr>
                """)
        infra_section_html = ""
        if infra_rows:
            infra_section_html = f"""
            <h2 style="font-size:17px; color:#0f172a; border-left:4px solid #0d9488; padding-left:10px; margin:28px 0 12px 0;">
                📊 Auditoria de Infraestrutura (SNMP, Impressoras & UPnP/SSDP)
            </h2>
            <table style="margin-bottom:24px;">
                <thead>
                    <tr>
                        <th>Endereço IP</th>
                        <th>Ativo</th>
                        <th>Categoria</th>
                        <th>Telemetria SNMP (Uptime / Portas / Toner / Páginas) & UPnP</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(infra_rows)}
                </tbody>
            </table>
            """

        rows = []
        for r in rec_list:
            status_badge = '<span style="color:#059669; font-weight:bold;">● Online</span>' if r.alive else '<span style="color:#94a3b8;">○ Offline</span>'
            ports_badges = "".join(f'<span style="background:#e0f2fe; color:#0369a1; padding:2px 6px; border-radius:4px; font-size:11px; margin-right:4px;">{p}</span>' for p in r.open_ports) or '<span style="color:#cbd5e1;">--</span>'
            cve_tag = f' <span style="background:#fee2e2; color:#991b1b; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:bold;">{r.risk_badge}</span>' if getattr(r, "risk_badge", "") else ""
            rows.append(f"""
            <tr style="border-bottom: 1px solid #f1f5f9;">
                <td style="padding: 10px 12px;">{status_badge}</td>
                <td style="padding: 10px 12px; font-weight: 600;">{r.hostname or '--'}{cve_tag}</td>
                <td style="padding: 10px 12px; font-family: monospace; color:#0969da; font-weight:bold;">{r.ip}</td>
                <td style="padding: 10px 12px;">{r.vendor or '<span style="color:#94a3b8;">Desconhecido</span>'}</td>
                <td style="padding: 10px 12px; font-family: monospace; color:#475569;">{r.mac or '--'}</td>
                <td style="padding: 10px 12px;">{r.format_ping()}</td>
                <td style="padding: 10px 12px;">{r.device_type or '--'}</td>
                <td style="padding: 10px 12px;">{ports_badges}</td>
            </tr>
            """)

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório Executivo de Auditoria de Rede — IP Scan IGT</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f8fafc;
            color: #1e293b;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1240px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.06);
            padding: 32px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .title h1 {{
            margin: 0 0 6px 0;
            font-size: 24px;
            color: #0f172a;
        }}
        .title p {{
            margin: 0;
            color: #64748b;
            font-size: 13px;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 14px 10px;
            text-align: center;
        }}
        .card .value {{
            font-size: 24px;
            font-weight: bold;
            color: #0969da;
            margin-top: 4px;
        }}
        .card .label {{
            font-size: 11px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 600;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background-color: #f1f5f9;
            padding: 12px;
            font-weight: 700;
            color: #475569;
            border-bottom: 2px solid #cbd5e1;
        }}
        .btn-print {{
            background-color: #0969da;
            color: #ffffff;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
            font-size: 13px;
        }}
        .btn-print:hover {{
            background-color: #0856b3;
        }}
        @media print {{
            body {{ background: #ffffff; padding: 0; }}
            .container {{ box-shadow: none; border-radius: 0; padding: 0; max-width: 100%; }}
            .btn-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">
                <h1>🌐 IP Scan IGT — Relatório Executivo de Auditoria & Segurança</h1>
                <p>Gerado em: <b>{now_str}</b> • Interface: <b>{iface_str}</b> • Versão: <b>{full_ver}</b></p>
            </div>
            <div>
                <button class="btn-print" onclick="window.print()">🖨️ Imprimir / Salvar em PDF</button>
            </div>
        </div>

        <div class="cards">
            <div class="card">
                <div class="label">Total Verificado</div>
                <div class="value">{total}</div>
            </div>
            <div class="card">
                <div class="label">Dispositivos Online</div>
                <div class="value" style="color: #059669;">{online}</div>
            </div>
            <div class="card">
                <div class="label">Score de Segurança</div>
                <div class="value" style="color: {sec_color}; font-size:20px;">{security_score}/100 ({sec_grade})</div>
            </div>
            <div class="card">
                <div class="label">Vulnerabilidades (CVE)</div>
                <div class="value" style="color: #dc2626;">{len(all_cves)}</div>
            </div>
            <div class="card">
                <div class="label">Ativos SNMP / UPnP</div>
                <div class="value" style="color: #0d9488;">{snmp_upnp_count}</div>
            </div>
            <div class="card">
                <div class="label">Câmeras / NVR ONVIF</div>
                <div class="value" style="color: #7c3aed;">{onvif_count}</div>
            </div>
        </div>

        <p style="font-size: 13px; color: #475569; margin-bottom: 16px;">
            <b>Principais Fabricantes na Rede:</b> {top_vendors_html}
        </p>

        {topo_section_html}
        {cve_section_html}
        {infra_section_html}

        <h2 style="font-size:17px; color:#0f172a; border-left:4px solid #0969da; padding-left:10px; margin:28px 0 12px 0;">
            📋 Inventário Completo de Dispositivos e Portas Abertas
        </h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Nome do Host</th>
                    <th>Endereço IP</th>
                    <th>Fabricante</th>
                    <th>Endereço MAC</th>
                    <th>Ping</th>
                    <th>Tipo / SO</th>
                    <th>Portas Abertas</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

    def export_results(self, fmt: str = "csv"):
        records_to_export = self.records if self.main_tabs.currentIndex() == 0 else self.fav_records
        if not records_to_export:
            QMessageBox.information(self, tr("export_dialog_title", "Exportar"), tr("export_no_results", "Nenhum resultado para exportar."))
            return

        filter_str = (
            f"{tr('export_filter_html', 'Relatório Executivo HTML (*.html)')};;"
            f"{tr('export_filter_csv', 'Arquivo CSV (*.csv)')};;"
            f"{tr('export_filter_json', 'Arquivo JSON (*.json)')};;"
            f"{tr('export_filter_txt', 'Arquivo TXT (*.txt)')}"
        )
        if fmt == "html":
            default_filter = tr("export_filter_html", "Relatório Executivo HTML (*.html)")
        elif fmt == "csv":
            default_filter = tr("export_filter_csv", "Arquivo CSV (*.csv)")
        elif fmt == "json":
            default_filter = tr("export_filter_json", "Arquivo JSON (*.json)")
        else:
            default_filter = tr("export_filter_txt", "Arquivo TXT (*.txt)")

        default_name = f"relatorio_rede.{fmt}"
        path, _ = QFileDialog.getSaveFileName(self, tr("export_dialog_title", "Exportar Resultados"), os.path.expanduser(f"~/{default_name}"), filter_str, default_filter)
        if not path:
            return

        try:
            if fmt == "html" or path.endswith(".html"):
                html_code = self.generate_executive_html_report(records_to_export)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(html_code)
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))
            elif fmt == "json":
                data = [dict(r.__dict__) for r in records_to_export.values()]
                for d in data:
                    d.pop("resources", None)
                    if "vulnerabilities" in d and isinstance(d["vulnerabilities"], list):
                        d["vulnerabilities"] = [
                            v.to_dict() if hasattr(v, "to_dict") else str(v)
                            for v in d["vulnerabilities"]
                        ]
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

    def show_changelog_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("IP Scan IGT — Histórico de Versões e Atualizações")
        dlg.resize(700, 540)
        vbox = QVBoxLayout(dlg)
        vbox.setContentsMargins(18, 18, 18, 18)
        vbox.setSpacing(12)

        title_color = "#38bdf8" if self.is_dark_mode else "#0969da"
        sub_color = "#94a3b8" if self.is_dark_mode else "#64748b"
        border_color = "#334155" if self.is_dark_mode else "#e2e8f0"
        body_color = "#f1f5f9" if self.is_dark_mode else "#1e293b"

        lbl_hdr = QLabel(f"<h2>Histórico de Versões do IP Scan IGT</h2><p style='color: {sub_color}; font-size: 13px;'>Versão ativa no sistema: <b style='color: {title_color};'>{get_full_version()}</b></p>")
        vbox.addWidget(lbl_hdr)

        text_edit = QTextBrowser()
        text_edit.setOpenExternalLinks(True)
        html = [f"<div style='font-family: Segoe UI, Noto Sans, sans-serif; line-height: 1.6; color: {body_color};'>"]
        for item in VERSION_HISTORY:
            html.append(f"<h3 style='color: {title_color}; margin-bottom: 2px;'>{item['version']} — {item['title']}</h3>")
            html.append(f"<p style='color: {sub_color}; font-size: 12px; margin-top: 0;'>Data de Lançamento: {item['date']}</p>")
            html.append("<ul style='margin-top: 4px;'>")
            for c in item["changes"]:
                html.append(f"<li style='margin-bottom: 5px;'>{c}</li>")
            html.append("</ul>")
            html.append(f"<hr style='border: none; border-top: 1px solid {border_color}; margin: 15px 0;'>")
        html.append("</div>")
        text_edit.setHtml("".join(html))
        vbox.addWidget(text_edit)

        btn_close = QPushButton("Fechar")
        btn_close.setFixedHeight(34)
        btn_close.setFixedWidth(110)
        btn_close.clicked.connect(dlg.accept)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        vbox.addLayout(btn_layout)

        dlg.exec_()

    def show_about_dialog(self):
        full_v = get_full_version()
        QMessageBox.about(
            self,
            "Sobre o IP Scan IGT",
            f"<h3>IP Scan IGT — {full_v}</h3>"
            f"<b>Data de Lançamento:</b> {APP_RELEASE_DATE}<br><br>"
            "Scanner profissional de IP e dispositivos de rede de alta velocidade construído para Linux e Windows.<br><br>"
            "<b>Destaques do Versionamento:</b><br>"
            f"• <b>Versão Ativa:</b> {full_v}<br>"
            "• <b>Auto-Identificação de Máscaras:</b> Cálculo automático em tempo real de CIDR e notação decimal (/24 • 255.255.255.0)<br>"
            "• <b>Atualização em 1 Clique:</b> Botão direto para buscar e sincronizar atualizações do GitHub<br>"
            "• <b>Suporte ONVIF & RTSP:</b> Detecção automática de câmeras de segurança e gravadores NVR com reprodução de vídeo via VLC/ffplay<br>"
            "• <b>Integração Nmap:</b> Auditoria profunda de portas e detecção de versões de serviços sem necessidade de sudo<br>"
            "• <b>Classificação Dinâmica:</b> Ordenação em 1 clique por IP numérico, Nome, Ping, MAC e Fabricante<br>"
            "• <b>Seletor de Placas de Rede:</b> Detecção e preenchimento automático para Ethernet, Wi-Fi, VPN e Bridges<br>"
            "• <b>Osciloscópio de Ping:</b> Monitor dinâmico em tempo real com gráfico sub-milissegundo.",
        )

    def closeEvent(self, event):
        if (
            not getattr(self, "_force_quit", False)
            and self.watchdog_cfg.get("minimize_to_tray", False)
            and self.tray_icon
            and self.tray_icon.isVisible()
            and os.environ.get("QT_QPA_PLATFORM") != "offscreen"
        ):
            self.hide()
            send_desktop_notification(
                "IP Scan IGT — Executando em Segundo Plano",
                "O aplicativo continua monitorando os ativos na Bandeja do Sistema.",
                is_critical=False,
                tray_icon=self.tray_icon,
            )
            event.ignore()
            return

        self.table_sweep_timer.stop()
        if hasattr(self, "watchdog_worker") and self.watchdog_worker and self.watchdog_worker.isRunning():
            self.watchdog_worker.stop()
            self.watchdog_worker.wait(500)
        if hasattr(self, "tray_icon") and self.tray_icon:
            self.tray_icon.hide()
        if hasattr(self, "_sweep_worker") and self._sweep_worker and self._sweep_worker.isRunning():
            self._sweep_worker.stop()
            self._sweep_worker.wait(500)
        self.live_ping_worker.stop()
        self.live_ping_worker.wait(500)
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait(1000)
        event.accept()


def main():
    try:
        app = QApplication(sys.argv)
        app.setApplicationName("IP Scan IGT")
        window = MainWindow()
        window.showMaximized()
        sys.exit(app.exec_())
    except Exception as err:
        import traceback
        tb = traceback.format_exc()
        print(f"\n[ERRO FATAL NA EXECUÇÃO]\n{tb}")
        if IS_WINDOWS:
            try:
                import ctypes
                ctypes.windll.user32.MessageBoxW(
                    0,
                    f"Erro fatal ao executar o IP Scan IGT:\n\n{err}\n\nDetalhes:\n{tb[:400]}",
                    "IP Scan IGT - Erro",
                    0x10,
                )
            except Exception:
                pass
            try:
                input("\nPressione ENTER para fechar esta janela...")
            except Exception:
                pass
        sys.exit(1)


if __name__ == "__main__":
    main()
