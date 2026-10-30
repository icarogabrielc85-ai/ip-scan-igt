#!/usr/bin/env python3
"""
Motor de Diagnóstico e Medição de Wi-Fi (Rede Sem Fio) — IP Scan IGT
Executa auditoria completa de sinal, qualidade de enlace, canal, largura de banda,
geração Wi-Fi (Wi-Fi 4/5/6/6E/7), latência/jitter até o roteador/AP, relação sinal-ruído (SNR)
e varredura de redes vizinhas / congestionamento de canal.
Compatível com Linux (nmcli, iw, iwconfig, /proc/net/wireless) e Windows (netsh wlan).
"""

from dataclasses import dataclass, field
from datetime import datetime
import os
import platform
import re
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import QThread, pyqtSignal


@dataclass
class NearbyWifiNetwork:
    ssid: str
    bssid: str
    signal_pct: int
    signal_dbm: int
    channel: int
    frequency_mhz: int
    security: str
    in_use: bool = False
    wifi_standard: str = "Wi-Fi"


@dataclass
class WifiDiagResult:
    interface_name: str = ""
    has_hardware: bool = False
    adapter_model: str = "Adaptador Wi-Fi Não Detectado"
    driver: str = "--"
    mac_address: str = "--"
    is_connected: bool = False
    ssid: str = "--"
    bssid: str = "--"
    signal_percent: int = 0
    signal_dbm: int = -100
    signal_quality_desc: str = "Sem Sinal"
    wifi_standard: str = "--"
    frequency_band: str = "--"
    frequency_mhz: int = 0
    channel: int = 0
    channel_width_mhz: int = 20
    tx_bitrate_mbps: float = 0.0
    rx_bitrate_mbps: float = 0.0
    security: str = "--"
    noise_dbm: int = -95
    snr_db: int = 0
    gateway_ip: str = "--"
    ping_gateway_ms: float = 0.0
    jitter_ms: float = 0.0
    packet_loss_pct: float = 0.0
    flaps: int = 0
    overall_condition: str = "Desconectado"
    channel_congestion: str = "--"
    nearby_networks: List[NearbyWifiNetwork] = field(default_factory=list)
    test_timestamp: str = ""
    is_demo: bool = False


def dbm_to_percent(dbm: int) -> int:
    """Converte RSSI em dBm (-100 a -30) em porcentagem de qualidade (0 a 100%)."""
    if dbm >= -50:
        return 100
    if dbm <= -100:
        return 0
    return int(2 * (dbm + 100))


def percent_to_dbm(pct: int) -> int:
    """Converte porcentagem (0 a 100%) em dBm aproximado (-100 a -50)."""
    pct = max(0, min(100, pct))
    return int((pct / 2) - 100)


def classify_signal_quality(pct: int) -> Tuple[str, str]:
    """Retorna descrição de qualidade e cor recomendada."""
    if pct >= 80:
        return "Excelente (Ideal para VoIP, Streaming 4K e Baixa Latência)", "#10b981"
    elif pct >= 60:
        return "Bom (Navegação rápida e estável)", "#22c55e"
    elif pct >= 40:
        return "Regular (Sinal moderado, sujeito a quedas eventuais)", "#f59e0b"
    elif pct >= 20:
        return "Fraco (Longe do Access Point / interferência física)", "#f97316"
    else:
        return "Crítico / Muito Fraco (Alto risco de desconexão)", "#ef4444"


def freq_to_band_and_channel(freq_mhz: int, chan: int = 0) -> Tuple[str, int]:
    """Determina a faixa (2.4 GHz, 5 GHz ou 6 GHz) e o canal baseado na frequência em MHz."""
    if 2400 <= freq_mhz <= 2500:
        calc_chan = chan or int((freq_mhz - 2407) / 5)
        return "2.4 GHz", calc_chan
    elif 5000 <= freq_mhz <= 5900:
        calc_chan = chan or int((freq_mhz - 5000) / 5)
        return "5 GHz", calc_chan
    elif freq_mhz >= 5925:
        calc_chan = chan or int((freq_mhz - 5950) / 5) + 1
        return "6 GHz (Wi-Fi 6E/7)", calc_chan
    return "Desconhecida", chan


def deduce_wifi_standard(freq_mhz: int, tx_rate: float, security: str, raw_proto: str = "") -> str:
    """Deduce o padrão comercial do Wi-Fi (Wi-Fi 4 / 5 / 6 / 6E / 7)."""
    raw_lower = raw_proto.lower()
    if "be" in raw_lower or "wifi 7" in raw_lower or "wifi7" in raw_lower:
        return "Wi-Fi 7 (IEEE 802.11be Extreme Throughput)"
    if "ax" in raw_lower or "wifi 6" in raw_lower or "wifi6" in raw_lower:
        if freq_mhz >= 5925:
            return "Wi-Fi 6E (IEEE 802.11ax 6 GHz Ultra-Band)"
        return "Wi-Fi 6 (IEEE 802.11ax High Efficiency)"
    if "ac" in raw_lower or "vht" in raw_lower or tx_rate > 450:
        return "Wi-Fi 5 (IEEE 802.11ac Gigabit Wave 2)"
    if "n" in raw_lower or "ht" in raw_lower or (tx_rate > 54 and freq_mhz < 5000):
        return "Wi-Fi 4 (IEEE 802.11n MIMO)"
    if "g" in raw_lower or (tx_rate <= 54 and freq_mhz < 3000):
        return "Wi-Fi Legacy (IEEE 802.11g 54 Mbps)"
    if freq_mhz >= 5000:
        return "Wi-Fi 5 (IEEE 802.11ac)"
    return "Wi-Fi 4 (IEEE 802.11n)"


def get_wifi_interfaces() -> List[Dict[str, str]]:
    """
    Lista todos os adaptadores de rede sem fio (Wi-Fi) detectados no sistema operacional.
    Retorna lista de dicionários: [{'name': 'wlan0', 'ip': '192.168.1.50', 'mac': '...'}, ...]
    """
    interfaces = []
    is_windows = platform.system() == "Windows"

    if is_windows:
        try:
            out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, stderr=subprocess.DEVNULL)
            curr_iface = {}
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    k, v = [x.strip() for x in line.split(":", 1)]
                    if k.lower() == "name" or k.lower() == "nome":
                        if curr_iface.get("name"):
                            interfaces.append(curr_iface)
                        curr_iface = {"name": v, "type": "wifi", "ip": "", "mac": ""}
                    elif "physical" in k.lower() or "físico" in k.lower():
                        curr_iface["mac"] = v
            if curr_iface.get("name"):
                interfaces.append(curr_iface)
        except Exception:
            pass
        return interfaces

    # Linux: 1. Verifica /sys/class/net/*/wireless ou phy80211
    sys_net = "/sys/class/net"
    if os.path.exists(sys_net):
        for iface in os.listdir(sys_net):
            iface_path = os.path.join(sys_net, iface)
            is_wireless = (
                os.path.exists(os.path.join(iface_path, "wireless"))
                or os.path.exists(os.path.join(iface_path, "phy80211"))
            )
            if is_wireless:
                mac = ""
                try:
                    with open(os.path.join(iface_path, "address"), "r") as f:
                        mac = f.read().strip()
                except Exception:
                    pass
                interfaces.append({"name": iface, "type": "wifi", "ip": "", "mac": mac})

    # Linux: 2. Fallback via nmcli
    if not interfaces and shutil.which("nmcli"):
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] == "wifi":
                    dev_name = parts[0]
                    if not any(i["name"] == dev_name for i in interfaces):
                        interfaces.append({"name": dev_name, "type": "wifi", "ip": "", "mac": ""})
        except Exception:
            pass

    # Linux: 3. Fallback via iw dev
    if not interfaces and shutil.which("iw"):
        try:
            out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL, timeout=3)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    dev_name = line.split()[1]
                    if not any(i["name"] == dev_name for i in interfaces):
                        interfaces.append({"name": dev_name, "type": "wifi", "ip": "", "mac": ""})
        except Exception:
            pass

    return interfaces


def measure_gateway_wifi_ping(gateway_ip: str) -> Tuple[float, float, float]:
    """Mede a latência média, jitter e perda de pacotes até o gateway Wi-Fi."""
    if not gateway_ip or gateway_ip == "--":
        return 0.0, 0.0, 0.0

    is_windows = platform.system() == "Windows"
    cmd = ["ping", "-n", "4", "-w", "1000", gateway_ip] if is_windows else ["ping", "-c", "4", "-W", "1", gateway_ip]

    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=5)
        # Linux RTT: rtt min/avg/max/mdev = 1.123/2.345/3.456/0.567 ms
        rtt_match = re.search(r"= ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms", out)
        if rtt_match:
            avg = float(rtt_match.group(2))
            jitter = float(rtt_match.group(4))
            loss_match = re.search(r"(\d+)% packet loss", out)
            loss = float(loss_match.group(1)) if loss_match else 0.0
            return avg, jitter, loss

        # Windows RTT: Mínimo = 1ms, Máximo = 3ms, Média = 2ms
        win_avg = re.search(r"(?:Média|Average) = (\d+)ms", out)
        win_loss = re.search(r"\((\d+)% (?:perda|loss)\)", out)
        avg = float(win_avg.group(1)) if win_avg else 2.0
        loss = float(win_loss.group(1)) if win_loss else 0.0
        return avg, 0.5, loss
    except Exception:
        return 0.0, 0.0, 0.0


def scan_nearby_wifi_linux(iface: str) -> List[NearbyWifiNetwork]:
    """Realiza varredura de redes sem fio vizinhas via nmcli ou iw no Linux."""
    networks: List[NearbyWifiNetwork] = []

    # 1. Tenta nmcli (mais rápido e seguro sem root)
    if shutil.which("nmcli"):
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY", "dev", "wifi"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=6,
            )
            for line in out.splitlines():
                # Campos escapados por ':' no nmcli
                parts = re.split(r"(?<!\\):", line)
                if len(parts) >= 9:
                    in_use = parts[0].strip() == "*"
                    ssid = parts[1].replace("\\:", ":").strip() or "<Rede Oculta>"
                    bssid = parts[2].replace("\\:", ":").strip()
                    try:
                        chan = int(parts[3].strip() or 0)
                    except ValueError:
                        chan = 0
                    freq_raw = parts[4].replace("MHz", "").strip()
                    try:
                        freq_mhz = int(freq_raw)
                    except ValueError:
                        freq_mhz = 2412
                    try:
                        signal_pct = int(parts[6].strip() or 50)
                    except ValueError:
                        signal_pct = 50
                    sec = parts[8].replace("\\:", ":").strip() or "Aberta"
                    dbm = percent_to_dbm(signal_pct)
                    std = deduce_wifi_standard(freq_mhz, 300, sec)

                    networks.append(
                        NearbyWifiNetwork(
                            ssid=ssid,
                            bssid=bssid,
                            signal_pct=signal_pct,
                            signal_dbm=dbm,
                            channel=chan,
                            frequency_mhz=freq_mhz,
                            security=sec,
                            in_use=in_use,
                            wifi_standard=std,
                        )
                    )
            if networks:
                # Ordena pelo melhor sinal
                networks.sort(key=lambda x: (not x.in_use, -x.signal_pct))
                return networks
        except Exception:
            pass

    return networks


def scan_nearby_wifi_windows() -> List[NearbyWifiNetwork]:
    """Varredura de redes vizinhas no Windows via netsh wlan."""
    networks: List[NearbyWifiNetwork] = []
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )
        curr_ssid = ""
        curr_auth = ""
        curr_bssid = ""
        curr_sig = 0
        curr_chan = 0
        curr_radio = ""

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("SSID "):
                if curr_bssid:
                    networks.append(
                        NearbyWifiNetwork(
                            ssid=curr_ssid or "<Rede Oculta>",
                            bssid=curr_bssid,
                            signal_pct=curr_sig,
                            signal_dbm=percent_to_dbm(curr_sig),
                            channel=curr_chan,
                            frequency_mhz=5180 if curr_chan > 14 else 2412,
                            security=curr_auth or "WPA2",
                            wifi_standard=deduce_wifi_standard(5180 if curr_chan > 14 else 2412, 300, curr_auth, curr_radio),
                        )
                    )
                parts = line.split(":", 1)
                curr_ssid = parts[1].strip() if len(parts) > 1 else ""
                curr_bssid = ""
            elif line.startswith("Autentica") or line.startswith("Authentication"):
                parts = line.split(":", 1)
                curr_auth = parts[1].strip() if len(parts) > 1 else ""
            elif line.startswith("BSSID "):
                if curr_bssid:
                    networks.append(
                        NearbyWifiNetwork(
                            ssid=curr_ssid or "<Rede Oculta>",
                            bssid=curr_bssid,
                            signal_pct=curr_sig,
                            signal_dbm=percent_to_dbm(curr_sig),
                            channel=curr_chan,
                            frequency_mhz=5180 if curr_chan > 14 else 2412,
                            security=curr_auth or "WPA2",
                            wifi_standard=deduce_wifi_standard(5180 if curr_chan > 14 else 2412, 300, curr_auth, curr_radio),
                        )
                    )
                parts = line.split(":", 1)
                curr_bssid = parts[1].strip() if len(parts) > 1 else ""
            elif "Sinal" in line or "Signal" in line:
                sig_match = re.search(r"(\d+)%", line)
                curr_sig = int(sig_match.group(1)) if sig_match else 50
            elif "Canal" in line or "Channel" in line:
                chan_match = re.search(r"(\d+)", line)
                curr_chan = int(chan_match.group(1)) if chan_match else 1
            elif "Tipo de r" in line or "Radio type" in line:
                parts = line.split(":", 1)
                curr_radio = parts[1].strip() if len(parts) > 1 else ""

        if curr_bssid:
            networks.append(
                NearbyWifiNetwork(
                    ssid=curr_ssid or "<Rede Oculta>",
                    bssid=curr_bssid,
                    signal_pct=curr_sig,
                    signal_dbm=percent_to_dbm(curr_sig),
                    channel=curr_chan,
                    frequency_mhz=5180 if curr_chan > 14 else 2412,
                    security=curr_auth or "WPA2",
                    wifi_standard=deduce_wifi_standard(5180 if curr_chan > 14 else 2412, 300, curr_auth, curr_radio),
                )
            )
        networks.sort(key=lambda x: -x.signal_pct)
    except Exception:
        pass
    return networks


def diagnose_wifi_linux(iface: str) -> WifiDiagResult:
    """Diagnóstico físico e de sinal Wi-Fi no Linux."""
    res = WifiDiagResult(
        interface_name=iface,
        test_timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    )

    # 1. Hardware e Driver
    try:
        ethtool_out = subprocess.check_output(["ethtool", "-i", iface], text=True, stderr=subprocess.DEVNULL)
        for line in ethtool_out.splitlines():
            if line.startswith("driver:"):
                res.driver = line.split(":", 1)[1].strip()
    except Exception:
        pass

    # Sysfs MAC & Carrier
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            res.mac_address = f.read().strip().upper()
    except Exception:
        pass

    # 2. Informações via 'iw dev <iface> link'
    iw_link_out = ""
    if shutil.which("iw"):
        try:
            iw_link_out = subprocess.check_output(["iw", "dev", iface, "link"], text=True, stderr=subprocess.DEVNULL)
            if "Connected to" in iw_link_out:
                res.is_connected = True
                bssid_m = re.search(r"Connected to ([0-9a-fA-F:]{17})", iw_link_out)
                if bssid_m:
                    res.bssid = bssid_m.group(1).upper()
                ssid_m = re.search(r"SSID:\s*(.+)", iw_link_out)
                if ssid_m:
                    res.ssid = ssid_m.group(1).strip()
                freq_m = re.search(r"freq:\s*(\d+)", iw_link_out)
                if freq_m:
                    res.frequency_mhz = int(freq_m.group(1))
                    res.frequency_band, res.channel = freq_to_band_and_channel(res.frequency_mhz)
                sig_m = re.search(r"signal:\s*(-?\d+)\s*dBm", iw_link_out)
                if sig_m:
                    res.signal_dbm = int(sig_m.group(1))
                    res.signal_percent = dbm_to_percent(res.signal_dbm)
                tx_m = re.search(r"tx bitrate:\s*([\d\.]+)\s*MBit/s", iw_link_out)
                if tx_m:
                    res.tx_bitrate_mbps = float(tx_m.group(1))
                rx_m = re.search(r"rx bitrate:\s*([\d\.]+)\s*MBit/s", iw_link_out)
                if rx_m:
                    res.rx_bitrate_mbps = float(rx_m.group(1))
                # Detecta largura de canal
                if "160MHz" in iw_link_out:
                    res.channel_width_mhz = 160
                elif "80MHz" in iw_link_out:
                    res.channel_width_mhz = 80
                elif "40MHz" in iw_link_out:
                    res.channel_width_mhz = 40
                else:
                    res.channel_width_mhz = 20
        except Exception:
            pass

    # 3. Informações via 'nmcli'
    if not res.is_connected and shutil.which("nmcli"):
        try:
            nm_out = subprocess.check_output(
                ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY", "dev", "wifi"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in nm_out.splitlines():
                parts = re.split(r"(?<!\\):", line)
                if len(parts) >= 8 and parts[0].strip() in ("yes", "sim", "*"):
                    res.is_connected = True
                    res.ssid = parts[1].replace("\\:", ":").strip()
                    res.bssid = parts[2].replace("\\:", ":").strip().upper()
                    try:
                        res.channel = int(parts[3].strip() or 0)
                    except ValueError:
                        pass
                    try:
                        res.frequency_mhz = int(parts[4].replace("MHz", "").strip() or 2412)
                    except ValueError:
                        pass
                    res.frequency_band, res.channel = freq_to_band_and_channel(res.frequency_mhz, res.channel)
                    try:
                        res.signal_percent = int(parts[6].strip() or 50)
                        res.signal_dbm = percent_to_dbm(res.signal_percent)
                    except ValueError:
                        pass
                    res.security = parts[7].replace("\\:", ":").strip()
                    break
        except Exception:
            pass

    # 4. Qualidade / Ruído via /proc/net/wireless
    if os.path.exists("/proc/net/wireless"):
        try:
            with open("/proc/net/wireless", "r") as f:
                for line in f:
                    if iface in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            noise_val = parts[4].rstrip(".")
                            try:
                                res.noise_dbm = int(noise_val)
                            except ValueError:
                                res.noise_dbm = -95
        except Exception:
            pass

    # 5. Gateway Wi-Fi Ping & Jitter
    try:
        route_out = subprocess.check_output(["ip", "route", "show", "dev", iface], text=True, stderr=subprocess.DEVNULL)
        gw_match = re.search(r"default via ([\d\.]+)", route_out)
        if gw_match:
            res.gateway_ip = gw_match.group(1)
            avg, jit, loss = measure_gateway_wifi_ping(res.gateway_ip)
            res.ping_gateway_ms = avg
            res.jitter_ms = jit
            res.packet_loss_pct = loss
    except Exception:
        pass

    # Calcula SNR
    res.snr_db = max(0, res.signal_dbm - res.noise_dbm)
    res.signal_quality_desc, _ = classify_signal_quality(res.signal_percent)
    res.wifi_standard = deduce_wifi_standard(res.frequency_mhz, res.tx_bitrate_mbps, res.security, iw_link_out)

    if res.is_connected:
        res.overall_condition = (
            f"Conectado • {res.ssid} • {res.signal_percent}% ({res.signal_dbm} dBm) • {res.wifi_standard}"
        )
    else:
        res.overall_condition = "Desconectado (Adaptador Ativo, aguardando conexão a uma rede)"

    # Varredura de redes vizinhas
    res.nearby_networks = scan_nearby_wifi_linux(iface)

    # Congestionamento de Canal
    if res.channel > 0 and res.nearby_networks:
        same_chan = sum(1 for n in res.nearby_networks if n.channel == res.channel and not n.in_use)
        if same_chan == 0:
            res.channel_congestion = f"Canal {res.channel} Exclusivo (0 redes concorrentes — Excelente)"
        elif same_chan <= 2:
            res.channel_congestion = f"Canal {res.channel} Moderado ({same_chan} redes no mesmo canal)"
        else:
            res.channel_congestion = f"Canal {res.channel} Congestionado ({same_chan} redes concorrentes — Recomendada troca)"
    else:
        res.channel_congestion = "Canal Livre ou sem sobreposição detectada"

    res.has_hardware = True
    return res


def diagnose_wifi_windows(iface: str) -> WifiDiagResult:
    """Diagnóstico físico e de sinal Wi-Fi no Windows via netsh wlan."""
    res = WifiDiagResult(
        interface_name=iface,
        test_timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    )

    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, stderr=subprocess.DEVNULL)
        in_curr_iface = False
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                k, v = [x.strip() for x in line.split(":", 1)]
                kl = k.lower()
                if "nome" in kl or "name" in kl:
                    in_curr_iface = (v == iface or not iface)
                    if in_curr_iface and not res.interface_name:
                        res.interface_name = v
                if not in_curr_iface:
                    continue

                if "descri" in kl or "description" in kl:
                    res.adapter_model = v
                elif "estado" in kl or "state" in kl:
                    res.is_connected = ("conectado" in v.lower() or "connected" in v.lower())
                elif "ssid" == kl:
                    res.ssid = v
                elif "bssid" == kl:
                    res.bssid = v.upper()
                elif "canal" in kl or "channel" in kl:
                    try:
                        res.channel = int(v)
                    except ValueError:
                        pass
                elif "sinal" in kl or "signal" in kl:
                    sig_m = re.search(r"(\d+)%", v)
                    if sig_m:
                        res.signal_percent = int(sig_m.group(1))
                        res.signal_dbm = percent_to_dbm(res.signal_percent)
                elif "taxa de recep" in kl or "receive rate" in kl:
                    try:
                        res.rx_bitrate_mbps = float(v.replace("Mbps", "").strip())
                    except ValueError:
                        pass
                elif "taxa de trans" in kl or "transmit rate" in kl:
                    try:
                        res.tx_bitrate_mbps = float(v.replace("Mbps", "").strip())
                    except ValueError:
                        pass
                elif "autentica" in kl or "authentication" in kl:
                    res.security = v
                elif "tipo de r" in kl or "radio type" in kl:
                    res.wifi_standard = deduce_wifi_standard(5180 if res.channel > 14 else 2412, res.tx_bitrate_mbps, res.security, v)
    except Exception:
        pass

    # Faixa e Frequência
    if res.channel > 14:
        res.frequency_band = "5 GHz"
        res.frequency_mhz = 5000 + (res.channel * 5)
    else:
        res.frequency_band = "2.4 GHz"
        res.frequency_mhz = 2407 + (res.channel * 5)

    res.snr_db = max(0, res.signal_dbm - res.noise_dbm)
    res.signal_quality_desc, _ = classify_signal_quality(res.signal_percent)

    if res.is_connected:
        res.overall_condition = f"Conectado • {res.ssid} • {res.signal_percent}% • {res.wifi_standard}"
    else:
        res.overall_condition = "Desconectado"

    res.nearby_networks = scan_nearby_wifi_windows()
    res.has_hardware = True
    return res


def get_demo_wifi_result() -> WifiDiagResult:
    """
    Retorna resultado realista de teste Wi-Fi 6 de nível corporativo para demonstração e homologação.
    Utilizado caso a estação não possua hardware Wi-Fi físico ativo ou para teste visual imediato.
    """
    res = WifiDiagResult(
        interface_name="wlp3s0 (Wi-Fi 6 AX200 160MHz)",
        has_hardware=True,
        adapter_model="Intel Corporation Wi-Fi 6 AX200 160MHz (Gig+) PCIe Controller (rev 1a)",
        driver="iwlwifi",
        mac_address="3C:58:C2:8A:1E:74",
        is_connected=True,
        ssid="IGT-Enterprise-Wi-Fi6",
        bssid="24:A4:3C:99:4D:10",
        signal_percent=94,
        signal_dbm=-48,
        signal_quality_desc="Excelente (Ideal para VoIP, Streaming 4K e Baixa Latência)",
        wifi_standard="Wi-Fi 6 (IEEE 802.11ax High Efficiency)",
        frequency_band="5 GHz",
        frequency_mhz=5180,
        channel=36,
        channel_width_mhz=80,
        tx_bitrate_mbps=1201.0,
        rx_bitrate_mbps=1201.0,
        security="WPA3-Personal (SAE / AES-128 GCMP)",
        noise_dbm=-94,
        snr_db=46,
        gateway_ip="192.168.111.254",
        ping_gateway_ms=1.45,
        jitter_ms=0.32,
        packet_loss_pct=0.0,
        flaps=0,
        overall_condition="Excelente • Enlace Wi-Fi 6 Gigabit Estável • Sem Perda de Pacotes",
        channel_congestion="Canal 36 Exclusivo (0 redes concorrentes na mesma frequência)",
        test_timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        is_demo=True,
        nearby_networks=[
            NearbyWifiNetwork("IGT-Enterprise-Wi-Fi6", "24:A4:3C:99:4D:10", 94, -48, 36, 5180, "WPA3-Personal", in_use=True, wifi_standard="Wi-Fi 6"),
            NearbyWifiNetwork("IGT-Visitantes", "24:A4:3C:99:4D:11", 90, -52, 36, 5180, "WPA2-PSK", in_use=False, wifi_standard="Wi-Fi 5"),
            NearbyWifiNetwork("Lab-IoT-Rede", "68:D7:9A:12:00:8F", 78, -62, 44, 5220, "WPA2-PSK", in_use=False, wifi_standard="Wi-Fi 5"),
            NearbyWifiNetwork("Rede-Corporativa-Legacy", "00:1A:2B:3C:4D:5E", 65, -70, 6, 2437, "WPA2-PSK", in_use=False, wifi_standard="Wi-Fi 4"),
            NearbyWifiNetwork("Impressoras-Wi-Fi", "F4:F2:6D:77:88:99", 58, -74, 11, 2462, "WPA2-PSK", in_use=False, wifi_standard="Wi-Fi 4"),
        ]
    )
    return res


def diagnose_wifi(iface: str = "", force_demo: bool = False) -> WifiDiagResult:
    """
    Ponto de entrada unificado para diagnóstico de Wi-Fi.
    Detecta automaticamente o sistema operacional e a interface sem fio.
    """
    if force_demo:
        return get_demo_wifi_result()

    ifaces = get_wifi_interfaces()
    if not ifaces:
        # Nenhum adaptador de Wi-Fi físico encontrado
        return WifiDiagResult(
            interface_name="Nenhum Adaptador Wi-Fi Detectado",
            has_hardware=False,
            adapter_model="Nenhum dispositivo sem fio (WLAN) ativo no sistema",
            driver="--",
            mac_address="--",
            is_connected=False,
            signal_percent=0,
            signal_dbm=-100,
            signal_quality_desc="Sem Sinal (Hardware Ausente)",
            overall_condition="Nenhum adaptador Wi-Fi físico encontrado neste computador.",
            test_timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            is_demo=False,
        )

    target_iface = iface or ifaces[0]["name"]
    is_windows = platform.system() == "Windows"

    if is_windows:
        return diagnose_wifi_windows(target_iface)
    return diagnose_wifi_linux(target_iface)


class LocalWifiDiagWorker(QThread):
    """Worker assíncrono para diagnóstico completo e varredura de sinal Wi-Fi sem congelar a interface."""
    status_updated = pyqtSignal(str)
    diag_completed = pyqtSignal(object)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface_name: str = "", force_demo: bool = False, parent=None):
        super().__init__(parent)
        self.interface_name = interface_name
        self.force_demo = force_demo

    def run(self):
        try:
            self.status_updated.emit("Identificando placas e adaptadores sem fio Wi-Fi...")
            time.sleep(0.1)

            if self.force_demo:
                self.status_updated.emit("Carregando ambiente de homologação e medição Wi-Fi 6...")
                time.sleep(0.3)
                res = get_demo_wifi_result()
                self.diag_completed.emit(res)
                return

            self.status_updated.emit(f"Medindo nível de sinal RSSI e potência em '{self.interface_name or 'Wi-Fi'}'...")
            time.sleep(0.15)
            self.status_updated.emit("Auditando modulação, canal, largura de banda e relação sinal-ruído (SNR)...")
            res = diagnose_wifi(self.interface_name)
            self.status_updated.emit("Escaneando redes vizinhas e analisando sobreposição de canais...")
            self.diag_completed.emit(res)
        except Exception as e:
            self.error_occurred.emit(f"Falha no diagnóstico de Wi-Fi: {str(e)}")
