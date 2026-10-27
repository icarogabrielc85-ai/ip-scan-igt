import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from i18n import tr

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"


def _get_windows_silent_kwargs() -> Dict[str, Any]:
    """Returns kwargs for subprocess execution without popping up console/cmd windows on Windows."""
    kwargs: Dict[str, Any] = {}
    if IS_WINDOWS:
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        if hasattr(subprocess, "STARTUPINFO"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = startupinfo
    return kwargs


def create_robust_ssl_context():
    """
    Creates an SSL context that works reliably across platforms,
    attempting certifi, system trust store, and falling back gracefully
    to avoid CERTIFICATE_VERIFY_FAILED in frozen or restricted environments.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass

    try:
        ctx = ssl.create_default_context()
        if hasattr(ctx, "load_default_certs"):
            ctx.load_default_certs()
        return ctx
    except Exception:
        pass

    try:
        return ssl._create_unverified_context()
    except Exception:
        return None


def robust_urlopen(url_or_req, timeout: float = 10, **kwargs):
    """
    Executes urllib.request.urlopen with fallback against SSL verification failures
    such as [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate
    which frequently occurs in Windows frozen executables or environments without certifi.
    """
    ctx = create_robust_ssl_context()
    try:
        if ctx:
            return urllib.request.urlopen(url_or_req, timeout=timeout, context=ctx, **kwargs)
        else:
            return urllib.request.urlopen(url_or_req, timeout=timeout, **kwargs)
    except Exception as exc:
        err_msg = str(exc).lower()
        if "certificate verify failed" in err_msg or "certificate_verify_failed" in err_msg or "local issuer certificate" in err_msg:
            try:
                unverified_ctx = ssl._create_unverified_context()
                return urllib.request.urlopen(url_or_req, timeout=timeout, context=unverified_ctx, **kwargs)
            except Exception:
                pass
        raise



from oui_db import OUI_DB
from onvif_engine import discover_onvif_devices, probe_onvif_unicast, probe_rtsp
from snmp_engine import probe_snmp
from cve_engine import CVE_DB, compute_risk_summary
from upnp_engine import UpnpDeviceInfo, discover_upnp_devices, probe_upnp_unicast

DEFAULT_PORTS = [
    21, 22, 23, 53, 80, 111, 139, 443, 445, 554,
    631, 2443, 3306, 3389, 3702, 5060, 5432, 5900, 8000, 8006, 8080, 8291, 8443, 8899, 9100
]

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP Web",
    111: "RPC/NFS",
    139: "NetBIOS",
    443: "HTTPS SSL",
    445: "SMB Windows",
    554: "RTSP Vídeo",
    631: "IPP Impressora",
    2443: "ONVIF/NVR",
    3306: "MySQL",
    3389: "RDP Windows",
    3702: "WS-Discovery",
    5060: "SIP VoIP",
    5432: "PostgreSQL",
    5900: "VNC",
    8000: "HTTP-Alt",
    8006: "Proxmox VE",
    8080: "HTTP-Proxy",
    8291: "MikroTik Winbox",
    8443: "HTTPS-Alt",
    8899: "ONVIF Câmera",
    9100: "JetDirect Impressora",
}


@dataclass
class ResourceItem:
    icon: str
    title: str
    detail: str
    url: str = ""


@dataclass
class HostRecord:
    ip: str
    alive: bool = False
    rtt_ms: float = -1.0
    ttl: int = -1
    ping_method: str = ""
    hostname: str = ""
    alias: str = ""
    mac: str = ""
    vendor: str = ""
    device_type: str = ""
    os_family: str = ""
    netbios_domain: str = ""
    http_info: str = ""
    ssl_info: str = ""
    ssh_banner: str = ""
    snmp_info: str = ""
    upnp_info: str = ""
    open_ports: List[int] = field(default_factory=list)
    resources: List[ResourceItem] = field(default_factory=list)
    comment: str = ""
    onvif_url: str = ""
    onvif_model: str = ""
    onvif_type: str = ""
    rtsp_url: str = ""
    nmap_services: Dict[int, str] = field(default_factory=dict)
    snmp_data: Dict[str, Any] = field(default_factory=dict)
    upnp_data: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Any] = field(default_factory=list)
    risk_level: str = "NONE"
    max_cvss: float = 0.0
    risk_badge: str = ""
    guard_alerts: List[Any] = field(default_factory=list)
    guard_badge: str = ""

    def format_ping(self) -> str:
        if not self.alive or self.rtt_ms < 0:
            return tr("status_offline", "Offline")
        if self.rtt_ms < 10.0:
            return f"{self.rtt_ms:.2f} ms"
        if self.rtt_ms < 100.0:
            return f"{self.rtt_ms:.1f} ms"
        return f"{self.rtt_ms:.0f} ms"

    def format_ports(self) -> str:
        if not self.open_ports:
            return ""
        return ", ".join(f"{p} ({PORT_SERVICES.get(p, 'TCP')})" for p in self.open_ports)

    def ip_sort_key(self) -> Tuple[int, ...]:
        try:
            return tuple(int(x) for x in self.ip.split("."))
        except Exception:
            return (999, 999, 999, 999)


ALIAS_STORE_PATH = os.path.expanduser("~/.config/ipscan-igt/device_aliases.json")
_ALIAS_CACHE: Optional[Dict[str, Dict[str, str]]] = None
_ALIAS_LOCK = threading.Lock()


def load_device_aliases(force_reload: bool = False) -> Dict[str, Dict[str, str]]:
    """Carrega o dicionário de apelidos personalizados por MAC e por IP com cache em memória."""
    global _ALIAS_CACHE
    with _ALIAS_LOCK:
        if _ALIAS_CACHE is not None and not force_reload:
            return {
                "by_mac": dict(_ALIAS_CACHE.get("by_mac") or {}),
                "by_ip": dict(_ALIAS_CACHE.get("by_ip") or {}),
            }
        try:
            if os.path.exists(ALIAS_STORE_PATH):
                with open(ALIAS_STORE_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        _ALIAS_CACHE = {
                            "by_mac": dict(data.get("by_mac") or {}),
                            "by_ip": dict(data.get("by_ip") or {}),
                        }
                        return {
                            "by_mac": dict(_ALIAS_CACHE["by_mac"]),
                            "by_ip": dict(_ALIAS_CACHE["by_ip"]),
                        }
        except Exception:
            pass
        _ALIAS_CACHE = {"by_mac": {}, "by_ip": {}}
        return {"by_mac": {}, "by_ip": {}}


def save_device_alias(ip: str, mac: str, alias: str) -> None:
    """Salva ou remove o apelido personalizado de um dispositivo vinculando por MAC e IP."""
    global _ALIAS_CACHE
    try:
        os.makedirs(os.path.dirname(ALIAS_STORE_PATH), exist_ok=True)
        store = load_device_aliases(force_reload=True)
        clean_alias = (alias or "").strip()
        norm_mac = (mac or "").strip().upper()
        clean_ip = (ip or "").strip()

        if norm_mac and norm_mac not in ("N/D", "N/A", "UNKNOWN", "00:00:00:00:00:00"):
            if clean_alias:
                store["by_mac"][norm_mac] = clean_alias
            else:
                store["by_mac"].pop(norm_mac, None)

        if clean_ip:
            if clean_alias:
                store["by_ip"][clean_ip] = clean_alias
            else:
                store["by_ip"].pop(clean_ip, None)

        with _ALIAS_LOCK:
            _ALIAS_CACHE = {
                "by_mac": dict(store["by_mac"]),
                "by_ip": dict(store["by_ip"]),
            }
            with open(ALIAS_STORE_PATH, "w", encoding="utf-8") as f:
                json.dump(store, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def get_device_alias(ip: str, mac: str = "") -> str:
    """Obtém o apelido salvo do dispositivo priorizando o endereço MAC e usando IP como fallback."""
    store = load_device_aliases()
    norm_mac = (mac or "").strip().upper()
    if norm_mac and norm_mac in store["by_mac"]:
        return store["by_mac"][norm_mac]
    if ip and ip in store["by_ip"]:
        return store["by_ip"][ip]
    return ""


def _find_sys_cmd(cmd_name: str) -> str:
    """Localiza binários de rede mesmo quando /sbin ou /usr/sbin não estão no PATH do ambiente gráfico."""
    found = shutil.which(cmd_name)
    if found:
        return found
    if not IS_WINDOWS:
        for prefix in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
            candidate = os.path.join(prefix, cmd_name)
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return cmd_name


def _is_valid_ipv4_netmask(mask_str: str) -> bool:
    """Valida se uma string é uma máscara de sub-rede IPv4 sintaticamente e semanticamente válida."""
    if not mask_str:
        return False
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{mask_str}")
        return True
    except Exception:
        return False


def _decode_console_output(raw: Any) -> str:
    """Decodifica saída de comandos de console no Windows/Linux preservando acentuação (OEM cp850, UTF-8, cp1252)."""
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw
    # UTF-8 primeiro (padrão Linux e consoles modernos), seguido de cp850 (OEM Windows BR/EU), cp1252, cp437
    for enc in ("utf-8", "cp850", "cp1252", "cp437", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _get_primary_outbound_ip() -> str:
    """
    Determina o endereço IPv4 local da placa principal de saída consultando a tabela
    de roteamento do kernel via socket UDP (sem transmitir pacotes na rede).
    """
    for target in (("8.8.8.8", 80), ("1.1.1.1", 53), ("192.168.1.1", 80), ("10.255.255.255", 1)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.2)
                s.connect(target)
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127.") and not ip.startswith("169.254.") and ip != "0.0.0.0":
                    return ip
        except Exception:
            continue
    return ""


def get_default_gateways() -> Dict[str, str]:
    gw_map: Dict[str, str] = {}
    if IS_WINDOWS:
        try:
            kwargs = _get_windows_silent_kwargs()
            raw = subprocess.check_output(["route", "print", "0.0.0.0"], timeout=2.0, **kwargs)
            out = _decode_console_output(raw)
            best_metric = 999999
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway = parts[2]
                    iface = parts[3]
                    metric = 100
                    if len(parts) >= 5 and parts[4].isdigit():
                        metric = int(parts[4])
                    gw_map[iface] = gateway
                    if metric < best_metric:
                        best_metric = metric
                        gw_map["default"] = gateway
                        gw_map["default_iface_ip"] = iface
        except Exception:
            pass
        return gw_map

    try:
        ip_bin = _find_sys_cmd("ip")
        out = subprocess.check_output([ip_bin, "-4", "route", "show", "default"], text=True, timeout=1.5)
        if not out.strip():
            out = subprocess.check_output([ip_bin, "route", "show"], text=True, timeout=1.5)
        for line in out.splitlines():
            parts = line.split()
            if not parts or parts[0] != "default":
                continue
            gw = ""
            dev = ""
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    gw = parts[idx + 1]
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    dev = parts[idx + 1]
            if dev:
                gw_map[dev] = gw or gw_map.get(dev, "")
                if "default" not in gw_map and gw:
                    gw_map["default"] = gw
    except Exception:
        pass

    # Fallback direto via /proc/net/route caso o binário `ip` não esteja disponível
    if not gw_map and os.path.exists("/proc/net/route"):
        try:
            with open("/proc/net/route", "r", encoding="utf-8", errors="ignore") as rf:
                for line in rf.read().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        iface = parts[0]
                        gw_hex = parts[2]
                        if len(gw_hex) == 8:
                            gw_int = int(gw_hex, 16)
                            gw_ip = socket.inet_ntoa(struct.pack("<L", gw_int))
                            gw_map[iface] = gw_ip
                            if "default" not in gw_map and gw_ip != "0.0.0.0":
                                gw_map["default"] = gw_ip
        except Exception:
            pass

    return gw_map


def _get_windows_network_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerate active IPv4 network interfaces on Windows using ipconfig /all,
    with encoding-independent regexes, multi-line IPv6/IPv4 gateway support,
    and fallback to netsh / socket resolution.
    """
    ifaces = []
    gw_map = get_default_gateways()
    primary_ip = _get_primary_outbound_ip()
    hostname = socket.gethostname()

    try:
        kwargs = _get_windows_silent_kwargs()
        raw = subprocess.check_output(["ipconfig", "/all"], timeout=3.0, **kwargs)
        out = _decode_console_output(raw)

        blocks = re.split(r"\r?\n(?=\S)", out)
        for block in blocks:
            lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
            if not lines:
                continue
            header = lines[0].rstrip(":")
            if any(w in header.lower() for w in ("configuration", "configura", "windows ip", "ip do windows")):
                continue

            name = header
            name_m = re.search(r"(?:adapter|adaptador|carte|scheda|адаптер)\s+(.+)", header, re.I)
            if name_m:
                name = name_m.group(1).strip()

            desc = ""
            mac = ""
            ipv4 = ""
            netmask = ""
            gateway = ""
            expecting_gw_continuation = False

            for line in lines[1:]:
                if expecting_gw_continuation:
                    if ":" not in line:
                        gw_cont = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                        if gw_cont:
                            gateway = gw_cont.group(1).strip()
                            expecting_gw_continuation = False
                        continue
                    else:
                        expecting_gw_continuation = False

                if not desc:
                    dm = re.search(r"(?:description|descri|beschreibung|description|описание)[^:]*:\s*(.+)$", line, re.I)
                    if dm:
                        desc = dm.group(1).strip()

                if not mac:
                    mm = re.search(r":\s*([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b", line)
                    if mm:
                        mac = mm.group(1).replace("-", ":").upper()

                if not ipv4:
                    # Captura IPv4 em qualquer idioma/codepage (ex: "IPv4 Address", "Endereço IPv4", "Endere‡o IPv4", "Dirección IPv4")
                    ipm = re.search(
                        r"(?:ipv4|ip\s*address|endere.{1,4}o\s*ip|direcci.{1,4}n\s*ip|indirizzo\s*ip|adresse\s*ip|ip-adresse|ip-\S+)[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})",
                        line,
                        re.I,
                    )
                    if ipm:
                        candidate_ip = ipm.group(1).strip()
                        if not candidate_ip.startswith("255."):
                            ipv4 = candidate_ip

                if not netmask:
                    smm = re.search(
                        r"(?:subnet|sub[- ]*rede|sub[- ]*red|mask|m.{0,4}sc[a-z]*|maschera|masque|maske|маска|掩码)[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})",
                        line,
                        re.I,
                    )
                    if smm and _is_valid_ipv4_netmask(smm.group(1).strip()):
                        netmask = smm.group(1).strip()

                if not gateway:
                    if re.search(r"(?:default\s*gateway|gateway\s*padr|puerta\s*de\s*enlace|gateway\s*predefinito|passerelle|standardgateway|шлюз|网关)", line, re.I):
                        gwm = re.search(r":\s*(\d{1,3}(?:\.\d{1,3}){3})", line)
                        if gwm:
                            gateway = gwm.group(1).strip()
                        else:
                            # No Windows 10/11 com IPv6 ativo, a primeira linha do Gateway Padrão traz fe80:: e a linha seguinte traz o IPv4
                            expecting_gw_continuation = True

            if not ipv4 or ipv4.startswith("127.") or ipv4.startswith("169.254."):
                continue

            try:
                mask = netmask if _is_valid_ipv4_netmask(netmask) else "255.255.255.0"
                net = ipaddress.IPv4Network(f"{ipv4}/{mask}", strict=False)
                start_ip, end_ip, total_hosts = _subnet_host_bounds(net, ipv4)
            except Exception:
                continue

            combined_desc = f"{name} {desc}".lower()
            is_virtual = any(
                k in combined_desc
                for k in ["vethernet", "virtualbox", "vmware", "hyper-v", "wsl", "loopback", "docker", "npcap", "bluetooth"]
            ) or ipv4.startswith("192.168.56.")

            if any(k in combined_desc for k in ["wi-fi", "wifi", "wireless", "sem fio", "802.11", "wlan"]):
                itype = "Wi-Fi (Sem Fio)"
                icon = "📶"
            elif any(k in combined_desc for k in ["vpn", "tap", "tun", "wireguard", "nord", "openvpn", "radmin", "zerotier", "tailscale", "hamachi"]):
                itype = "VPN / Túnel"
                icon = "🛡️"
            elif is_virtual:
                itype = "Bridge / Virtual"
                icon = "🖥️"
            elif any(k in combined_desc for k in ["ethernet", "gbe", "gigabit", "pcie", "realtek", "intel", "lan", "broadcom", "killer"]):
                itype = "Ethernet (Cabeada)"
                icon = "🌐"
            else:
                itype = "Rede Local"
                icon = "🔌"

            is_primary = (ipv4 == primary_ip) or (ipv4 == gw_map.get("default_iface_ip"))
            is_default = is_primary or (bool(gateway) and not is_virtual) or (ipv4 in gw_map and not is_virtual)
            gw_val = gateway or gw_map.get(ipv4, "") or gw_map.get(name, "") or (gw_map.get("default", "") if is_default else "")

            vendor = ""
            if mac:
                vendor = OUI_DB.lookup(mac)

            ifaces.append({
                "name": name,
                "interface": name,
                "ip": ipv4,
                "cidr": str(net.prefixlen),
                "netmask": str(net.netmask),
                "network": str(net.network_address),
                "start_ip": start_ip,
                "end_ip": end_ip,
                "total_hosts": total_hosts,
                "mac": mac,
                "vendor": vendor,
                "type": itype,
                "icon": icon,
                "speed": "",
                "gateway": gw_val,
                "is_default": is_default,
                "_is_primary": is_primary,
                "_is_virtual": is_virtual,
                "hostname": hostname,
            })
    except Exception as e:
        print("Error reading Windows interfaces via ipconfig:", e)

    if not ifaces:
        try:
            ip_candidates: List[str] = []
            if primary_ip:
                ip_candidates.append(primary_ip)
            _, _, ip_list = socket.gethostbyname_ex(hostname)
            for ip_str in ip_list:
                if ip_str not in ip_candidates:
                    ip_candidates.append(ip_str)
            for ip_str in ip_candidates:
                if ip_str.startswith("127.") or ip_str.startswith("169.254.") or ":" in ip_str:
                    continue
                net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                start_ip, end_ip, total_hosts = _subnet_host_bounds(net, ip_str)
                is_virt = ip_str.startswith("192.168.56.")
                ifaces.append({
                    "name": "Ethernet",
                    "interface": "Ethernet",
                    "ip": ip_str,
                    "cidr": "24",
                    "netmask": "255.255.255.0",
                    "network": str(net.network_address),
                    "start_ip": start_ip,
                    "end_ip": end_ip,
                    "total_hosts": total_hosts,
                    "mac": "",
                    "vendor": "",
                    "type": "Bridge / Virtual" if is_virt else "Ethernet (Cabeada)",
                    "icon": "🖥️" if is_virt else "🌐",
                    "speed": "",
                    "gateway": gw_map.get(ip_str, "") or gw_map.get("default", ""),
                    "is_default": (ip_str == primary_ip) or not is_virt,
                    "_is_primary": ip_str == primary_ip,
                    "_is_virtual": is_virt,
                    "hostname": hostname,
                })
        except Exception:
            pass

    ifaces.sort(
        key=lambda x: (
            not x.get("_is_primary", False),
            not x.get("is_default", False),
            x.get("_is_virtual", False),
            x.get("name", ""),
        )
    )
    return ifaces


def _subnet_host_bounds(net: ipaddress.IPv4Network, fallback_ip: str) -> Tuple[str, str, int]:
    """Calcula O(1) o primeiro IP, último IP e total de hosts da sub-rede sem alocar milhões de objetos."""
    num = int(net.num_addresses)
    if num <= 2:
        return str(net.network_address) or fallback_ip, str(net.broadcast_address) or fallback_ip, max(1, num)
    return str(net.network_address + 1), str(net.broadcast_address - 1), num - 2


def _get_linux_ioctl_interfaces(gw_map: Dict[str, str], primary_ip: str, hostname: str) -> List[Dict[str, Any]]:
    """Fallback em Python puro via ioctl SIOCGIFADDR / SIOCGIFNETMASK direto no kernel Linux."""
    ifaces: List[Dict[str, Any]] = []
    if IS_WINDOWS or not os.path.exists("/sys/class/net"):
        return ifaces
    try:
        import fcntl
        for name in sorted(os.listdir("/sys/class/net")):
            if name == "lo":
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    ifreq = struct.pack("256s", name[:15].encode("utf-8"))
                    ip_bytes = fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24]  # SIOCGIFADDR
                    mask_bytes = fcntl.ioctl(s.fileno(), 0x891B, ifreq)[20:24]  # SIOCGIFNETMASK
                    ip_str = socket.inet_ntoa(ip_bytes)
                    mask_str = socket.inet_ntoa(mask_bytes)
                    if ip_str.startswith("127.") or ip_str.startswith("169.254."):
                        continue
                    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                    start_ip, end_ip, total_hosts = _subnet_host_bounds(net, ip_str)
                    is_virt = name.startswith(("docker", "br", "veth", "virbr", "cni", "vboxnet", "vmnet"))
                    is_primary = ip_str == primary_ip
                    is_default = is_primary or (name in gw_map and not is_virt)
                    ifaces.append({
                        "name": name,
                        "interface": name,
                        "ip": ip_str,
                        "cidr": str(net.prefixlen),
                        "netmask": str(net.netmask),
                        "network": str(net.network_address),
                        "start_ip": start_ip,
                        "end_ip": end_ip,
                        "total_hosts": total_hosts,
                        "mac": "",
                        "vendor": "",
                        "type": "Bridge / Virtual" if is_virt else "Ethernet (Cabeada)",
                        "icon": "🖥️" if is_virt else "🌐",
                        "speed": "",
                        "gateway": gw_map.get(name, "") or (gw_map.get("default", "") if is_default else ""),
                        "is_default": is_default,
                        "_is_primary": is_primary,
                        "_is_virtual": is_virt,
                        "hostname": hostname,
                    })
            except Exception:
                continue
    except Exception:
        pass
    return ifaces


def get_all_network_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerate all active IPv4 network interfaces on Linux or Windows.
    Returns detailed properties including interface name, IP, CIDR, netmask,
    subnet range, MAC address, vendor, interface type, speed and gateway.
    """
    if IS_WINDOWS:
        return _get_windows_network_interfaces()

    ifaces = []
    gw_map = get_default_gateways()
    primary_ip = _get_primary_outbound_ip()
    hostname = socket.gethostname()

    try:
        ip_bin = _find_sys_cmd("ip")
        out = subprocess.check_output(
            [ip_bin, "-o", "-4", "addr", "show", "up"],
            text=True,
            timeout=2.0,
        )
        if not out.strip():
            out = subprocess.check_output(
                [ip_bin, "-o", "-4", "addr", "show"],
                text=True,
                timeout=2.0,
            )
        for line in out.splitlines():
            m_inet = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\b", line)
            if not m_inet:
                continue
            ip_str = m_inet.group(1)
            prefix = m_inet.group(2)
            if ip_str.startswith("127.") or ip_str.startswith("169.254."):
                continue

            parts = line.split()
            name = parts[1].rstrip(":") if len(parts) >= 2 else "eth0"
            m_name = re.match(r"^\d+:\s+([^\s:]+)", line)
            if m_name:
                name = m_name.group(1)
            if "@" in name:
                name = name.split("@", 1)[0]

            try:
                net = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
                start_ip, end_ip, total_hosts = _subnet_host_bounds(net, ip_str)
            except Exception:
                continue

            mac = ""
            mac_path = f"/sys/class/net/{name}/address"
            if os.path.exists(mac_path):
                try:
                    with open(mac_path) as mf:
                        mac = mf.read().strip().upper()
                except Exception:
                    pass

            is_virtual = name.startswith(("docker", "br", "veth", "virbr", "cni", "vboxnet", "vmnet"))

            # Interface classification & icon
            if os.path.exists(f"/sys/class/net/{name}/wireless") or name.startswith("wl"):
                itype = "Wi-Fi (Sem Fio)"
                icon = "📶"
            elif name.startswith(("tun", "tap", "wg", "tailscale", "zt")):
                itype = "VPN / Túnel"
                icon = "🛡️"
            elif is_virtual:
                itype = "Bridge / Virtual"
                icon = "🖥️"
            elif name.startswith(("en", "eth", "em")):
                itype = "Ethernet (Cabeada)"
                icon = "🌐"
            else:
                itype = "Rede Local"
                icon = "🔌"

            speed = ""
            speed_path = f"/sys/class/net/{name}/speed"
            if os.path.exists(speed_path):
                try:
                    with open(speed_path) as sf:
                        s = int(sf.read().strip())
                        if s > 0:
                            speed = f"{s} Mbps"
                except Exception:
                    pass

            is_primary = ip_str == primary_ip
            is_default = is_primary or (name in gw_map and not is_virtual)
            gw = gw_map.get(name, "") or (gw_map.get("default", "") if is_default else "")

            vendor = ""
            if mac:
                vendor = OUI_DB.lookup(mac)

            ifaces.append({
                "name": name,
                "interface": name,
                "ip": ip_str,
                "cidr": prefix,
                "netmask": str(net.netmask),
                "network": str(net.network_address),
                "start_ip": start_ip,
                "end_ip": end_ip,
                "total_hosts": total_hosts,
                "mac": mac,
                "vendor": vendor,
                "type": itype,
                "icon": icon,
                "speed": speed,
                "gateway": gw,
                "is_default": is_default,
                "_is_primary": is_primary,
                "_is_virtual": is_virtual,
                "hostname": hostname,
            })
    except Exception as e:
        print("Error reading network interfaces:", e)

    if not ifaces:
        try:
            ifconfig_bin = _find_sys_cmd("ifconfig")
            out_if = subprocess.check_output([ifconfig_bin], text=True, timeout=2.0)
            cur_name = ""
            for line in out_if.splitlines():
                if line and not line.startswith(" ") and not line.startswith("\t"):
                    cur_name = line.split(":")[0].split()[0].strip()
                if "inet " in line:
                    ip_m = re.search(r"inet\s+(?:addr:|end\.:\s*)?(\d{1,3}(?:\.\d{1,3}){3})", line, re.I)
                    nm_m = re.search(r"(?:netmask|mask:|m[aá\u00a0\ufffd\?]?scara:?)\s*(\d{1,3}(?:\.\d{1,3}){3})", line, re.I)
                    if ip_m:
                        ip_val = ip_m.group(1)
                        raw_mask = nm_m.group(1) if nm_m else ""
                        mask_val = raw_mask if _is_valid_ipv4_netmask(raw_mask) else "255.255.255.0"
                        if not ip_val.startswith("127.") and not ip_val.startswith("169.254."):
                            net = ipaddress.IPv4Network(f"{ip_val}/{mask_val}", strict=False)
                            start_ip, end_ip, total_hosts = _subnet_host_bounds(net, ip_val)
                            is_virt = (cur_name or "").startswith(("docker", "br", "veth", "virbr", "vboxnet"))
                            is_prim = ip_val == primary_ip
                            ifaces.append({
                                "name": cur_name or "eth0",
                                "interface": cur_name or "eth0",
                                "ip": ip_val,
                                "cidr": str(net.prefixlen),
                                "netmask": str(net.netmask),
                                "network": str(net.network_address),
                                "start_ip": start_ip,
                                "end_ip": end_ip,
                                "total_hosts": total_hosts,
                                "mac": "",
                                "vendor": "",
                                "type": "Bridge / Virtual" if is_virt else "Ethernet (Cabeada)",
                                "icon": "🖥️" if is_virt else "🌐",
                                "speed": "",
                                "gateway": gw_map.get(cur_name, "") or (gw_map.get("default", "") if is_prim else ""),
                                "is_default": is_prim or (cur_name in gw_map and not is_virt),
                                "_is_primary": is_prim,
                                "_is_virtual": is_virt,
                                "hostname": hostname,
                            })
        except Exception:
            pass

    if not ifaces:
        ifaces = _get_linux_ioctl_interfaces(gw_map, primary_ip, hostname)

    # Sort primary outbound interface first, then default gateway interface, then physical before virtual
    ifaces.sort(
        key=lambda x: (
            not x.get("_is_primary", False),
            not x.get("is_default", False),
            x.get("_is_virtual", False),
            x.get("name", ""),
        )
    )
    return ifaces


def get_local_network_info(interface_name: Optional[str] = None) -> Dict[str, Any]:
    all_ifaces = get_all_network_interfaces()
    if interface_name:
        for iface in all_ifaces:
            if iface["name"] == interface_name:
                return iface
    if all_ifaces:
        return all_ifaces[0]

    primary_ip = _get_primary_outbound_ip() or "192.168.1.100"
    try:
        net = ipaddress.IPv4Network(f"{primary_ip}/24", strict=False)
        start_ip, end_ip, total_hosts = _subnet_host_bounds(net, primary_ip)
    except Exception:
        start_ip, end_ip, total_hosts = "192.168.1.1", "192.168.1.254", 254

    return {
        "interface": "eth0",
        "name": "eth0",
        "ip": primary_ip,
        "cidr": "24",
        "netmask": "255.255.255.0",
        "start_ip": start_ip,
        "end_ip": end_ip,
        "total_hosts": total_hosts,
        "mac": "",
        "hostname": socket.gethostname(),
        "type": "Ethernet",
        "icon": "🌐",
    }


def send_wake_on_lan(mac_address: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> bool:
    """
    Envia Magic Packet padrão Wake-on-LAN (IEEE 802.3) para ligar computadores remotamente pela rede.
    """
    try:
        clean_mac = re.sub(r"[^0-9a-fA-F]", "", mac_address)
        if len(clean_mac) != 12:
            return False
        mac_bytes = bytes.fromhex(clean_mac)
        magic_packet = b"\xff" * 6 + mac_bytes * 16
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic_packet, (broadcast_ip, port))
            if broadcast_ip != "255.255.255.255":
                try:
                    s.sendto(magic_packet, ("255.255.255.255", port))
                except Exception:
                    pass
        return True
    except Exception as e:
        print("Erro ao enviar Wake-on-LAN:", e)
        return False


_ARP_CACHE: Dict[str, str] = {}
_ARP_CACHE_TS: float = 0.0
_ARP_LOCK = threading.Lock()


def read_arp_table() -> Dict[str, str]:
    global _ARP_CACHE, _ARP_CACHE_TS
    now = time.monotonic()
    with _ARP_LOCK:
        if _ARP_CACHE and (now - _ARP_CACHE_TS) < 0.6:
            return dict(_ARP_CACHE)

    arp_map: Dict[str, str] = {}
    if IS_WINDOWS:
        try:
            kwargs = _get_windows_silent_kwargs()
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=2.0, **kwargs)
            for line in out.splitlines():
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
                if m:
                    ip_str = m.group(1)
                    mac_str = m.group(2).replace("-", ":").upper()
                    if mac_str not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                        arp_map[ip_str] = mac_str
        except Exception:
            pass
        with _ARP_LOCK:
            _ARP_CACHE = dict(arp_map)
            _ARP_CACHE_TS = time.monotonic()
        return arp_map

    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as f:
            for line in f.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip_str, mac = parts[0], parts[3].upper()
                    if mac != "00:00:00:00:00:00" and ":" in mac:
                        arp_map[ip_str] = mac
    except Exception:
        pass

    try:
        out = subprocess.check_output(["ip", "neigh", "show"], text=True, timeout=1.5)
        for line in out.splitlines():
            m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]{17})", line)
            if m:
                arp_map[m.group(1)] = m.group(2).upper()
    except Exception:
        pass

    with _ARP_LOCK:
        _ARP_CACHE = dict(arp_map)
        _ARP_CACHE_TS = time.monotonic()
    return arp_map

read_linux_arp_table = read_arp_table


_TIME_RE = re.compile(r"(?:time|tempo)[=<]([0-9]+(?:[.,][0-9]+)?)\s*ms", re.I)
_TTL_RE = re.compile(r"ttl[=:](\d+)", re.I)


def probe_ping(ip: str, timeout_ms: int = 600, fallback_ports: Optional[List[int]] = None) -> Tuple[bool, float, int, str]:
    try:
        t0 = time.perf_counter()
        kwargs = {}
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip]
            kwargs.update(_get_windows_silent_kwargs())
            wait_sec = max(0.6, (timeout_ms / 1000.0) + 0.5)
        else:
            ping_w = str(round(max(0.2, timeout_ms / 1000.0), 2))
            cmd = ["ping", "-n", "-c", "1", "-W", ping_w, ip]
            wait_sec = max(0.5, timeout_ms / 1000.0 + 0.3)

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=wait_sec,
            **kwargs,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if proc.returncode == 0:
            out = proc.stdout
            rtt = elapsed_ms
            tm = _TIME_RE.search(out)
            if tm:
                rtt = float(tm.group(1).replace(",", "."))
            ttl = -1
            ttlm = _TTL_RE.search(out)
            if ttlm:
                ttl = int(ttlm.group(1))
            return True, rtt, ttl, "ICMP"
    except Exception:
        pass

    ports = fallback_ports if fallback_ports else [80, 443, 22, 445]
    for port in ports:
        t0 = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=min(0.4, timeout_ms / 1000.0)):
                rtt = (time.perf_counter() - t0) * 1000.0
                return True, rtt, -1, f"TCP:{port}"
        except ConnectionRefusedError:
            rtt = (time.perf_counter() - t0) * 1000.0
            return True, rtt, -1, "TCP-RST"
        except Exception:
            pass

    return False, -1.0, -1, ""


def scan_host_ports(ip: str, ports: List[int] = DEFAULT_PORTS, timeout: float = 0.28) -> List[int]:
    open_list: List[int] = []

    def check_port(p: int) -> Optional[int]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, p)) == 0:
                    return p
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(24, len(ports))) as ex:
        for res in ex.map(check_port, ports):
            if res is not None:
                open_list.append(res)
    return sorted(open_list)


def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for part in name.split("."):
        b = part.encode("utf-8")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    pos = offset
    jumps = 0
    jumped = False
    next_offset = offset

    while pos < len(data):
        length = data[pos]
        if length == 0:
            if not jumped:
                next_offset = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data) or jumps > 12:
                break
            if not jumped:
                next_offset = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            jumped = True
            jumps += 1
            continue
        pos += 1
        labels.append(data[pos : pos + length].decode("utf-8", errors="ignore"))
        pos += length
    return ".".join(labels), next_offset


def resolve_mdns_or_llmnr(ip: str, port: int = 5353, timeout: float = 0.35) -> str:
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        req_id = 0x1337
        qclass = 0x8001 if port == 5353 else 0x0001
        packet = struct.pack(">HHHHHH", req_id, 0, 1, 0, 0, 0) + _encode_dns_name(rev) + struct.pack(">HH", 12, qclass)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(packet, (ip, port))
            except Exception:
                pass
            try:
                mcast = "224.0.0.251" if port == 5353 else "224.0.0.252"
                s.sendto(packet, (mcast, port))
            except Exception:
                pass

            deadline = time.time() + timeout
            while time.time() < deadline:
                remaining = max(0.05, deadline - time.time())
                s.settimeout(remaining)
                try:
                    resp, addr = s.recvfrom(1024)
                except socket.timeout:
                    break
                if len(resp) < 12:
                    continue
                rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", resp[:12])
                if ancount == 0 or (rid != req_id and addr[0] != ip):
                    continue
                pos = 12
                for _ in range(qdcount):
                    _, pos = _decode_dns_name(resp, pos)
                    pos += 4
                for _ in range(ancount):
                    _, pos = _decode_dns_name(resp, pos)
                    if pos + 10 > len(resp):
                        break
                    rtype, _, _, rdlen = struct.unpack(">HHIH", resp[pos : pos + 10])
                    pos += 10
                    if rtype == 12 and rdlen > 0:
                        name, _ = _decode_dns_name(resp, pos)
                        if name:
                            return name.rstrip(".")
                    pos += rdlen
    except Exception:
        pass
    return ""


def resolve_netbios(ip: str, timeout: float = 0.35) -> Tuple[str, str, str]:
    """Returns (computer_name, workgroup, mac)"""
    req = bytes([
        0xA2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
        0x00, 0x01
    ])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(req, (ip, 137))
            resp, _ = s.recvfrom(1024)
            if len(resp) < 57 or resp[47] != 33:
                return "", "", ""
            count = resp[56]
            if len(resp) < 57 + count * 18:
                return "", "", ""
            comp_name = ""
            group_name = ""
            for i in range(count):
                base = 57 + i * 18
                raw_name = resp[base : base + 15].decode("latin-1", errors="ignore").strip()
                ntype = resp[base + 15]
                nflag = (resp[base + 16] << 8) | resp[base + 17]
                is_group = (nflag & 0x8000) != 0
                if not is_group and not comp_name and raw_name and not raw_name.startswith("\x01"):
                    comp_name = raw_name
                elif is_group and ntype == 0x00 and not group_name and raw_name:
                    group_name = raw_name
            mac_pos = 57 + count * 18
            mac = ""
            if mac_pos + 6 <= len(resp):
                mac_bytes = resp[mac_pos : mac_pos + 6]
                if mac_bytes != b"\x00\x00\x00\x00\x00\x00":
                    mac = ":".join(f"{b:02X}" for b in mac_bytes)
            return comp_name, group_name, mac
    except Exception:
        return "", "", ""


def resolve_smb_ntlmssp(ip: str, timeout: float = 0.45) -> Tuple[str, str, str]:
    """Extracts (nb_computer, nb_domain, dns_computer) from SMB2 NTLMSSP challenge on TCP 445."""
    smb2_neg = bytes([
        0x00, 0x00, 0x00, 0x6C,
        0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        0xDD, 0xEE, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03
    ])
    smb2_setup = bytes([
        0x00, 0x00, 0x00, 0x78,
        0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x58, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x07, 0x82, 0x08, 0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])
    try:
        with socket.create_connection((ip, 445), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(smb2_neg)
            hdr = s.recv(4)
            if len(hdr) < 4:
                return "", "", ""
            plen = struct.unpack(">I", hdr)[0] & 0xFFFFFF
            _ = s.recv(plen)

            s.sendall(smb2_setup)
            hdr = s.recv(4)
            if len(hdr) < 4:
                return "", "", ""
            plen = struct.unpack(">I", hdr)[0] & 0xFFFFFF
            buf = bytearray()
            while len(buf) < plen:
                chunk = s.recv(plen - len(buf))
                if not chunk:
                    break
                buf.extend(chunk)
            data = bytes(buf)
            idx = data.find(b"NTLMSSP\x00\x02\x00\x00\x00")
            if idx < 0 or idx + 48 > len(data):
                return "", "", ""
            tinfo_len, _, tinfo_off = struct.unpack("<HHI", data[idx + 40 : idx + 48])
            pos = idx + tinfo_off
            end = min(len(data), pos + tinfo_len)
            nb_comp, nb_dom, dns_comp = "", "", ""
            while pos + 4 <= end:
                avid, avlen = struct.unpack("<HH", data[pos : pos + 4])
                pos += 4
                if avid == 0 or avlen <= 0 or pos + avlen > end:
                    break
                val = data[pos : pos + avlen].decode("utf-16le", errors="ignore").strip()
                if avid == 1:
                    nb_comp = val
                elif avid == 2:
                    nb_dom = val
                elif avid == 3:
                    dns_comp = val
                pos += avlen
            return nb_comp, nb_dom, dns_comp
    except Exception:
        return "", "", ""


def inspect_http_service(ip: str, port: int = 80, timeout: float = 0.5) -> Tuple[str, str]:
    """Returns (model_or_title, server_header)"""
    title = ""
    server = ""
    raw = ""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii"))
            chunks = []
            total = 0
            while total < 8192:
                try:
                    data = s.recv(2048)
                    if not data:
                        break
                    chunks.append(data)
                    total += len(data)
                    if b"\r\n\r\n" in data and b"</" in data.lower():
                        break
                except socket.timeout:
                    break
            raw = b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return "", ""

    if not raw:
        return "", ""

    sm = re.search(r"(?im)^Server:\s*([^\r\n]+)", raw)
    if sm:
        server = sm.group(1).strip()

    tm = re.search(r"(?is)<title[^>]*>\s*([^<]+?)\s*</title>", raw)
    if tm:
        cand = re.sub(r"\s+", " ", tm.group(1)).strip()
        if not _is_generic_title(cand):
            title = cand

    if not title and ("TP-LINK" in server.upper() or "product-tag" in raw or "login-body" in raw):
        try:
            url = f"http://{ip}:{port}/data/login.json"
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                jdata = json.loads(resp.read().decode("utf-8", errors="ignore"))
                dut = jdata.get("dutMode", "").strip()
                if dut:
                    title = f"TP-Link {dut}"
        except Exception:
            pass
        if not title:
            pm = re.search(r'(?is)id=["\']product-tag["\'][^>]*>.*?<span\s+class=["\']text["\']>\s*([^<]+?)\s*</span>', raw)
            if pm:
                title = "TP-Link " + re.sub(r"\s+", " ", pm.group(1)).strip()

    if not title:
        rm = re.search(r'(?im)^WWW-Authenticate:.*realm="([^"]+)"', raw)
        if rm:
            cand = rm.group(1).strip()
            if not _is_generic_title(cand):
                title = cand

    return title, server


def inspect_ssl_certificate(ip: str, port: int = 443, timeout: float = 0.5) -> str:
    # 1. Pure Python stdlib SSL certificate inspection (Cross-Platform)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    import tempfile
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".pem") as tf:
                        tf.write(pem)
                        tf_path = tf.name
                    try:
                        d = ssl._ssl._test_decode_cert(tf_path)
                        for item in d.get("subject", ()):
                            for k, v in item:
                                if k == "commonName" and v and v != "*" and v != ip and str(v).lower() != "localhost":
                                    return str(v)
                        for kind, name in d.get("subjectAltName", ()):
                            if kind == "DNS" and name and name != "*" and name != ip:
                                return str(name)
                    finally:
                        try:
                            os.remove(tf_path)
                        except Exception:
                            pass
    except Exception:
        pass

    # 2. Linux fallback using openssl CLI if available
    if not IS_WINDOWS and shutil.which("openssl"):
        try:
            proc = subprocess.run(
                ["bash", "-c", f"timeout 1 openssl s_client -connect {ip}:{port} </dev/null 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null"],
                capture_output=True,
                text=True,
                timeout=1.2,
            )
            out = proc.stdout.strip()
            if out:
                cn_m = re.search(r"CN\s*=\s*([^\s,/]+)", out)
                if cn_m:
                    cn = cn_m.group(1).strip()
                    if cn and cn != "*" and cn != ip and cn.lower() != "localhost":
                        return cn
        except Exception:
            pass

    return ""


def inspect_ssh_banner(ip: str, timeout: float = 0.35) -> str:
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as s:
            s.settimeout(timeout)
            lines = s.recv(128).decode("utf-8", errors="ignore").splitlines()
            if lines:
                line = lines[0].strip()
                if line.startswith("SSH-"):
                    return re.sub(r"^SSH-[0-9.]+-", "", line)
    except Exception:
        pass
    return ""


def _is_generic_title(s: str) -> bool:
    if not s:
        return True
    low = s.lower()
    bad = ["404", "403", "401", "301", "302", "not found", "forbidden", "moved", "error", "redirect", "index of", "document", "welcome", "login"]
    return any(b in low for b in bad)


def correlate_host_vulnerabilities(rec: HostRecord):
    """Cruza os metadados do host com a base SQLite de CVEs e atualiza os indicadores de risco."""
    vulns = CVE_DB.correlate_host(
        open_ports=rec.open_ports,
        http_info=rec.http_info,
        ssh_banner=rec.ssh_banner,
        ssl_info=rec.ssl_info,
        snmp_info=rec.snmp_info,
        vendor=rec.vendor,
        onvif_model=rec.onvif_model,
        nmap_services=rec.nmap_services,
    )
    rec.vulnerabilities = vulns
    rec.risk_level, rec.max_cvss, rec.risk_badge = compute_risk_summary(vulns)


def classify_device(rec: HostRecord) -> Tuple[str, str]:
    correlate_host_vulnerabilities(rec)
    v = (rec.vendor or "").lower()
    h = (rec.http_info or "").lower()
    s = (rec.ssl_info or "").lower()
    snmp = (rec.snmp_info or "").lower()
    upnp = (rec.upnp_info or "").lower()
    p = rec.open_ports

    # ONVIF Security Cameras & NVRs
    if rec.onvif_url or rec.onvif_model:
        is_nvr = "nvr" in (rec.onvif_type or "").lower() or "nvr" in (rec.onvif_model or "").lower()
        if is_nvr:
            return tr("dev_nvr", "📹 Gravador NVR (ONVIF)"), f"NVR ({rec.onvif_model or rec.vendor or 'ONVIF'})"
        return tr("dev_ipc", "📹 Câmera IP (ONVIF)"), f"ONVIF ({rec.onvif_model or rec.vendor or 'IPC'})"

    if 554 in p or 8899 in p or 2443 in p:
        return tr("dev_rtsp", "📹 Câmera de Vídeo / RTSP"), f"RTSP / IP Video ({rec.vendor or 'RTSP'})"

    if "eap" in h or "omada" in s or ("tp-link" in v and (80 in p or 443 in p)):
        return tr("dev_ap_router", "📡 Access Point / Roteador"), "TP-Link Omada / Linux Embedded"
    if "yealink" in v or 5060 in p:
        return tr("dev_voip", "📞 Telefone IP VoIP"), f"VoIP SIP ({rec.vendor or 'SIP'})"
    if 8006 in p:
        return tr("dev_proxmox", "🖥️ Hipervisor Proxmox VE"), "Debian Linux (Proxmox VE)"
    if "proxmox" in v:
        if 445 in p or 3389 in p or (64 < rec.ttl <= 128):
            return tr("dev_vm_win", "💻 VM Windows (Proxmox)"), "Microsoft Windows (VM)"
        if 22 in p:
            return tr("dev_vm_linux", "🐧 VM / LXC Linux (Proxmox)"), f"Linux ({rec.ssh_banner or 'Proxmox VM'})"
        return tr("dev_vm_container", "🖥️ VM / Contêiner (Proxmox)"), "Virtualizado Proxmox VE"
    if 9100 in p or 631 in p or any(k in snmp for k in ["laserjet", "officejet", "printer", "toner"]):
        return tr("dev_printer", "🖨️ Impressora de Rede"), "IPP / JetDirect / SNMP"
    if 8291 in p or any(k in snmp for k in ["routeros", "mikrotik", "cisco ios", "edgeos", "procurve", "jetstream"]):
        return tr("dev_switch_router", "🖧 Switch / Roteador de Rede"), rec.snmp_info.split("•")[0].strip() if rec.snmp_info else "Network OS"
    if upnp and any(k in upnp for k in ["tv", "bravia", "webos", "tizen", "roku", "chromecast", "dlna", "mediarenderer"]):
        return tr("dev_smart_tv", "📺 Smart TV / Mídia UPnP"), rec.upnp_info.split("•")[0].strip()
    if rec.netbios_domain or 445 in p or 3389 in p or (64 < rec.ttl <= 128):
        return tr("dev_win", "💻 Estação / Servidor Windows"), "Microsoft Windows"
    if 22 in p or rec.ssh_banner:
        return tr("dev_linux_ssh", "🐧 Servidor Linux / SSH"), rec.ssh_banner or "Linux / Unix"
    if rec.ttl > 128:
        return tr("dev_switch_router", "🖧 Switch / Roteador de Rede"), f"Network OS (TTL {rec.ttl})"
    if 0 < rec.ttl <= 64:
        return tr("dev_linux_embedded", "🐧 Dispositivo Linux / Embarcado"), f"Linux / Embedded (TTL {rec.ttl})"
    if rec.vendor:
        return tr("dev_network_dev", "🔌 Dispositivo de Rede"), rec.vendor
    return tr("dev_host_online", "🖧 Host Online"), tr("unknown", "Desconhecido")


def build_resources_for_host(rec: HostRecord) -> List[ResourceItem]:
    correlate_host_vulnerabilities(rec)
    items: List[ResourceItem] = []
    na = tr("not_available", "N/D")
    if rec.onvif_url:
        model_name = rec.onvif_model or tr("dev_ipc", "Câmera IP")
        items.append(ResourceItem("📹", tr("res_onvif", "Serviço ONVIF (Device Service)"), f"{tr('dns_field_name', 'Modelo')}: {model_name}", rec.onvif_url))
    if rec.rtsp_url or 554 in rec.open_ports:
        rtsp = rec.rtsp_url or f"rtsp://{rec.ip}:554/"
        items.append(ResourceItem("🎬", tr("res_rtsp_title", "Stream de Vídeo RTSP (Porta 554)"), tr("res_rtsp_detail", "Transmissão H.264/H.265 em Tempo Real (VLC)"), rtsp))
    if 8899 in rec.open_ports and not rec.onvif_url:
        items.append(ResourceItem("📹", tr("res_onvif_ctrl_title", "Porta ONVIF de Controle (8899)"), tr("res_onvif_ctrl_detail", "Serviço SOAP de Gerenciamento"), f"http://{rec.ip}:8899/onvif/device_service"))
    if 2443 in rec.open_ports and not rec.onvif_url:
        items.append(ResourceItem("📹", tr("res_nvr_secure_title", "Painel NVR Seguro (2443)"), tr("res_nvr_secure_detail", "Interface de Gerenciamento do Gravador"), f"https://{rec.ip}:2443/"))

    if 80 in rec.open_ports or rec.http_info:
        items.append(ResourceItem("🌐", tr("res_http_title", "Painel / Serviço Web HTTP (Porta 80)"), rec.http_info or tr("active_http", "Servidor HTTP Ativo"), f"http://{rec.ip}/"))
    if 8080 in rec.open_ports:
        items.append(ResourceItem("🌐", tr("res_http_alt_title", "Serviço Web HTTP-Alt (Porta 8080)"), tr("res_http_alt_detail", "Interface Web Alternativa"), f"http://{rec.ip}:8080/"))
    if 443 in rec.open_ports or rec.ssl_info:
        detail = f"{tr('ssl_cert', 'Certificado SSL')}: CN={rec.ssl_info}" if rec.ssl_info else tr("active_https", "HTTPS Ativo")
        items.append(ResourceItem("🔒", tr("res_https_title", "Serviço Web Seguro HTTPS (Porta 443)"), detail, f"https://{rec.ip}/"))
    if 8006 in rec.open_ports:
        items.append(ResourceItem("🖥️", tr("res_proxmox_title", "Console Web Proxmox VE (Porta 8006)"), tr("res_proxmox_desc", "Gerenciamento Virtualização"), f"https://{rec.ip}:8006/"))
    if 8443 in rec.open_ports:
        items.append(ResourceItem("🔒", tr("res_https_alt_title", "Painel HTTPS Alternativo (Porta 8443)"), tr("res_https_alt_desc", "Controladora / Admin"), f"https://{rec.ip}:8443/"))
    if 445 in rec.open_ports or 139 in rec.open_ports or rec.netbios_domain:
        items.append(ResourceItem("📁", tr("res_smb_title", "Compartilhamento de Arquivos SMB / Windows"), rec.netbios_domain or f"{tr('ports_label', 'Portas')} 445", f"smb://{rec.ip}/"))
    if 21 in rec.open_ports:
        items.append(ResourceItem("📂", tr("res_ftp_title", "Servidor de Arquivos FTP (Porta 21)"), tr("res_ftp_desc", "Transferência de Arquivos"), f"ftp://{rec.ip}/"))
    if 3389 in rec.open_ports:
        items.append(ResourceItem("🖥️", tr("res_rdp_title", "Área de Trabalho Remota RDP (Porta 3389)"), tr("res_rdp_desc", "Microsoft Remote Desktop Ativo"), f"rdp://{rec.ip}"))
    if 22 in rec.open_ports or rec.ssh_banner:
        items.append(ResourceItem("💻", tr("res_ssh_title", "Servidor SSH (Porta 22)"), rec.ssh_banner or tr("res_ssh_desc", "Acesso Terminal SSH Remoto"), f"ssh://{rec.ip}"))
    if rec.snmp_info:
        items.append(ResourceItem("📊", tr("res_snmp_title", "Auditoria SNMP (UDP 161)"), rec.snmp_info, ""))
    if rec.upnp_info:
        upnp_url = (rec.upnp_data or {}).get("presentation_url") or (rec.upnp_data or {}).get("location") or ""
        items.append(ResourceItem("📡", tr("res_upnp_title", "Descoberta UPnP / SSDP (UDP 1900)"), rec.upnp_info, upnp_url))
    if rec.vulnerabilities:
        for v in rec.vulnerabilities:
            v_icon = "🚨" if v.severity == "CRITICAL" else ("⚠️" if v.severity == "HIGH" else "🛡️")
            items.append(
                ResourceItem(
                    v_icon,
                    f"{tr('res_cve_alert', 'Alerta CVE')}: {v.cve_id} ({v.severity} • CVSS {v.cvss:.1f})",
                    f"{v.title} — {v.remediation}",
                    "",
                )
            )
    if rec.guard_alerts:
        for ga in rec.guard_alerts:
            g_icon = "🚨" if getattr(ga, "severity", "") == "CRITICAL" else "⚠️"
            items.append(
                ResourceItem(
                    g_icon,
                    f"Network Guard: {getattr(ga, 'alert_type', 'ALERTA')}",
                    getattr(ga, "details", ""),
                    "",
                )
            )
    if rec.mac or rec.vendor:
        items.append(ResourceItem("🏷️", tr("res_hardware_title", "Hardware / Placa de Rede"), f"MAC: {rec.mac or na}  •  {tr('col_manufacturer', 'Fabricante')}: {rec.vendor or na}", ""))
    if rec.open_ports:
        items.append(ResourceItem("🔌", tr("res_open_ports_title", "Portas TCP Abertas"), rec.format_ports(), ""))
    return items


def scan_single_ip(
    ip: str,
    arp_table: Dict[str, str],
    local_info: Dict[str, str],
    onvif_cache: Optional[Dict[str, dict]] = None,
    scan_dead: bool = False,
    upnp_cache: Optional[Dict[str, UpnpDeviceInfo]] = None,
) -> Optional[HostRecord]:
    rec = HostRecord(ip=ip)
    is_self = ip == local_info.get("ip")

    if is_self:
        rec.mac = local_info.get("mac", "")
        rec.hostname = local_info.get("hostname", "")
    elif ip in arp_table:
        rec.mac = arp_table[ip]

    alive, rtt, ttl, method = probe_ping(ip, timeout_ms=550)
    if not alive and rec.mac:
        # Host is present in Linux ARP table even if blocking ICMP/TCP ping!
        alive = True
        rtt = 0.35
        method = "ARP-L2"

    rec.alive = alive
    rec.rtt_ms = rtt
    rec.ttl = ttl
    rec.ping_method = method

    if not alive and not scan_dead:
        return None

    # Merge ONVIF discovery info if pre-discovered via multicast
    if onvif_cache and ip in onvif_cache:
        ov = onvif_cache[ip]
        rec.onvif_url = ov.get("xaddrs", "")
        rec.onvif_model = ov.get("hardware") or ov.get("name", "")
        rec.onvif_type = ov.get("category", "")
        rec.rtsp_url = ov.get("rtsp_url", f"rtsp://{ip}:554/")
        if ov.get("mac") and not rec.mac:
            rec.mac = ov["mac"]
        if not rec.hostname or rec.hostname.startswith("Host ["):
            rec.hostname = f"{rec.onvif_model} ({ip})"

    # Merge UPnP / SSDP discovery info if pre-discovered via multicast
    if upnp_cache and ip in upnp_cache:
        up_dev = upnp_cache[ip]
        rec.upnp_info = up_dev.format_summary()
        rec.upnp_data = up_dev.to_dict()
        if not rec.vendor and up_dev.manufacturer:
            rec.vendor = up_dev.manufacturer
        if not rec.hostname and up_dev.friendly_name:
            rec.hostname = up_dev.friendly_name

    # Refresh MAC from kernel ARP table after ping triggered ARP resolution
    if not rec.mac:
        fresh_arp = read_linux_arp_table()
        if ip in fresh_arp:
            rec.mac = fresh_arp[ip]

    if rec.mac:
        rec.vendor = OUI_DB.lookup(rec.mac) or OUI_DB.lookup_online(rec.mac) or rec.vendor

    # Scan TCP ports
    rec.open_ports = scan_host_ports(ip)
    if rec.open_ports and not rec.alive:
        rec.alive = True

    # Check for RTSP & ONVIF if video ports are open
    if 554 in rec.open_ports or 8899 in rec.open_ports or 2443 in rec.open_ports or 3702 in rec.open_ports:
        if (not rec.onvif_url or not rec.onvif_model) and (8899 in rec.open_ports or 2443 in rec.open_ports or 3702 in rec.open_ports):
            ov_uni = probe_onvif_unicast(ip)
            if ov_uni:
                rec.onvif_url = ov_uni.get("xaddrs", "")
                rec.onvif_model = ov_uni.get("hardware") or ov_uni.get("name", "")
                rec.onvif_type = ov_uni.get("category", "")
                if ov_uni.get("rtsp_url"):
                    rec.rtsp_url = ov_uni["rtsp_url"]
                if ov_uni.get("mac") and not rec.mac:
                    rec.mac = ov_uni["mac"]
                    rec.vendor = OUI_DB.lookup(rec.mac) or OUI_DB.lookup_online(rec.mac)
                if not rec.hostname or rec.hostname.startswith("Host ["):
                    rec.hostname = f"{rec.onvif_model} ({ip})"

        if 554 in rec.open_ports and not rec.rtsp_url:
            is_rtsp, srv_b = probe_rtsp(ip)
            if is_rtsp:
                rec.rtsp_url = f"rtsp://{ip}:554/"

    # Deep service inspection
    if 80 in rec.open_ports or 8080 in rec.open_ports:
        h_port = 80 if 80 in rec.open_ports else 8080
        title, srv = inspect_http_service(ip, h_port)
        if title and srv:
            rec.http_info = f"{title} [{srv}]"
        else:
            rec.http_info = title or srv

    if 443 in rec.open_ports or 8006 in rec.open_ports or 8443 in rec.open_ports:
        s_port = 443 if 443 in rec.open_ports else (8006 if 8006 in rec.open_ports else 8443)
        rec.ssl_info = inspect_ssl_certificate(ip, s_port)

    if 22 in rec.open_ports:
        rec.ssh_banner = inspect_ssh_banner(ip)

    # SNMP (UDP 161) Infrastructure & Printer Audit
    snmp_res = probe_snmp(ip, timeout=0.30)
    if snmp_res.enabled:
        rec.snmp_info = snmp_res.format_summary()
        rec.snmp_data = snmp_res.to_dict()
        if not rec.hostname and snmp_res.sys_name:
            rec.hostname = snmp_res.sys_name

    # Unicast UPnP fallback if not pre-discovered via multicast
    if not rec.upnp_info:
        up_uni = probe_upnp_unicast(ip, timeout=0.22)
        if up_uni:
            rec.upnp_info = up_uni.format_summary()
            rec.upnp_data = up_uni.to_dict()
            if not rec.vendor and up_uni.manufacturer:
                rec.vendor = up_uni.manufacturer
            if not rec.hostname and up_uni.friendly_name:
                rec.hostname = up_uni.friendly_name

    # Multi-layer Hostname resolution
    if not rec.hostname:
        try:
            h, _, _ = socket.gethostbyaddr(ip)
            if h and h != ip:
                rec.hostname = h
        except Exception:
            pass

    nb_comp, nb_group, nb_mac = resolve_netbios(ip)
    if nb_mac and not rec.mac:
        rec.mac = nb_mac
        rec.vendor = OUI_DB.lookup(rec.mac) or OUI_DB.lookup_online(rec.mac)
    if nb_group or nb_comp:
        rec.netbios_domain = f"{nb_group}\\{nb_comp}".strip("\\")
    if not rec.hostname and nb_comp:
        rec.hostname = nb_comp

    if 445 in rec.open_ports:
        smb_comp, smb_dom, smb_dns = resolve_smb_ntlmssp(ip)
        if smb_dom or smb_comp:
            rec.netbios_domain = f"{smb_dom}\\{smb_comp}".strip("\\")
        if not rec.hostname and (smb_comp or smb_dns):
            rec.hostname = smb_comp or smb_dns

    if not rec.hostname:
        rec.hostname = resolve_mdns_or_llmnr(ip, 5355)
    if not rec.hostname:
        rec.hostname = resolve_mdns_or_llmnr(ip, 5353)

    if not rec.hostname and rec.http_info:
        prefix = rec.http_info.split(" [")[0].strip()
        if prefix and not prefix.upper().startswith("TP-LINK HTTPD"):
            rec.hostname = f"{prefix} ({rec.ssl_info})" if rec.ssl_info else prefix

    if not rec.hostname and rec.ssl_info:
        rec.hostname = rec.ssl_info

    if not rec.hostname and rec.mac:
        suffix = rec.mac[-5:]
        if rec.vendor:
            rec.hostname = f"{rec.vendor} [{suffix}]"
        else:
            rec.hostname = f"Host [{suffix}]"

    if not rec.alias:
        rec.alias = get_device_alias(rec.ip, rec.mac)
    rec.device_type, rec.os_family = classify_device(rec)
    rec.resources = build_resources_for_host(rec)
    return rec
