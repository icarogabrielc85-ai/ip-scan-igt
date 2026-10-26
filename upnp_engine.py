import concurrent.futures
import re
import socket
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, Optional

SSDP_MULTICAST_ADDR = "239.255.255.250"
SSDP_PORT = 1900


@dataclass
class UpnpDeviceInfo:
    ip: str
    location: str = ""
    server: str = ""
    st: str = ""
    usn: str = ""
    friendly_name: str = ""
    manufacturer: str = ""
    model_name: str = ""
    model_number: str = ""
    serial_number: str = ""
    device_type: str = ""
    presentation_url: str = ""

    def format_summary(self) -> str:
        parts = []
        if self.friendly_name:
            parts.append(self.friendly_name)
        model_full = " ".join(x for x in [self.model_name, self.model_number] if x).strip()
        if model_full and model_full.lower() not in (self.friendly_name or "").lower():
            parts.append(model_full)
        if self.manufacturer and self.manufacturer.lower() not in " ".join(parts).lower():
            parts.append(f"Fab: {self.manufacturer}")
        if self.serial_number:
            parts.append(f"S/N: {self.serial_number}")
        if not parts and self.server:
            parts.append(self.server)
        return " • ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "location": self.location,
            "server": self.server,
            "st": self.st,
            "usn": self.usn,
            "friendly_name": self.friendly_name,
            "manufacturer": self.manufacturer,
            "model_name": self.model_name,
            "model_number": self.model_number,
            "serial_number": self.serial_number,
            "device_type": self.device_type,
            "presentation_url": self.presentation_url,
            "summary": self.format_summary(),
        }


def parse_ssdp_headers(raw_response: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in raw_response.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def parse_upnp_xml(xml_content: str, base_location: str = "") -> Dict[str, str]:
    """
    Faz o parse seguro do XML de descrição UPnP (RootDevice),
    extraindo friendlyName, manufacturer, modelName, modelNumber, serialNumber e presentationURL.
    """
    info: Dict[str, str] = {}
    if not xml_content:
        return info
    try:
        root = ET.fromstring(xml_content.strip())
        # Procura o primeiro bloco <device>
        device_elem = None
        for elem in root.iter():
            local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if local_name.lower() == "device":
                device_elem = elem
                break

        target_iter = device_elem.iter() if device_elem is not None else root.iter()
        for elem in target_iter:
            local_name = (elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag).lower()
            val = (elem.text or "").strip()
            if not val:
                continue
            if local_name == "friendlyname" and "friendly_name" not in info:
                info["friendly_name"] = val
            elif local_name == "manufacturer" and "manufacturer" not in info:
                info["manufacturer"] = val
            elif local_name == "modelname" and "model_name" not in info:
                info["model_name"] = val
            elif local_name == "modelnumber" and "model_number" not in info:
                info["model_number"] = val
            elif local_name == "serialnumber" and "serial_number" not in info:
                info["serial_number"] = val
            elif local_name == "devicetype" and "device_type" not in info:
                info["device_type"] = val
            elif local_name == "presentationurl" and "presentation_url" not in info:
                if val.startswith("http://") or val.startswith("https://"):
                    info["presentation_url"] = val
                elif base_location:
                    info["presentation_url"] = urllib.parse.urljoin(base_location, val)
    except Exception:
        pass
    return info


def fetch_upnp_xml_details(dev: UpnpDeviceInfo, timeout: float = 0.55) -> UpnpDeviceInfo:
    if not dev.location or not (dev.location.startswith("http://") or dev.location.startswith("https://")):
        return dev
    try:
        req = urllib.request.Request(
            dev.location,
            headers={"User-Agent": "IPScanIGT/2.9 UPnP/1.1"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_bytes = resp.read(65536)
            xml_str = raw_bytes.decode("utf-8", errors="ignore")
            parsed = parse_upnp_xml(xml_str, base_location=dev.location)
            dev.friendly_name = parsed.get("friendly_name", dev.friendly_name)
            dev.manufacturer = parsed.get("manufacturer", dev.manufacturer)
            dev.model_name = parsed.get("model_name", dev.model_name)
            dev.model_number = parsed.get("model_number", dev.model_number)
            dev.serial_number = parsed.get("serial_number", dev.serial_number)
            dev.device_type = parsed.get("device_type", dev.device_type)
            dev.presentation_url = parsed.get("presentation_url", dev.presentation_url)
    except Exception:
        pass
    return dev


def _build_msearch_packet(st: str = "upnp:rootdevice", mx: int = 1) -> bytes:
    msg = (
        f"M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_MULTICAST_ADDR}:{SSDP_PORT}\r\n"
        f"MAN: \"ssdp:discover\"\r\n"
        f"MX: {mx}\r\n"
        f"ST: {st}\r\n"
        f"\r\n"
    )
    return msg.encode("ascii")


def discover_upnp_devices(timeout: float = 1.0) -> Dict[str, UpnpDeviceInfo]:
    """
    Executa descoberta multicast SSDP (UDP 1900) na rede local e resolve os XMLs UPnP.
    Retorna dicionário {ip: UpnpDeviceInfo}.
    """
    discovered: Dict[str, UpnpDeviceInfo] = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.25)

        for st in ("upnp:rootdevice", "ssdp:all"):
            try:
                sock.sendto(_build_msearch_packet(st=st, mx=1), (SSDP_MULTICAST_ADDR, SSDP_PORT))
            except Exception:
                pass

        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                hdrs = parse_ssdp_headers(text)
                loc = hdrs.get("location", "")
                srv = hdrs.get("server", "")
                st_val = hdrs.get("st", "")
                usn_val = hdrs.get("usn", "")

                if ip not in discovered:
                    discovered[ip] = UpnpDeviceInfo(
                        ip=ip,
                        location=loc,
                        server=srv,
                        st=st_val,
                        usn=usn_val,
                    )
                else:
                    if loc and not discovered[ip].location:
                        discovered[ip].location = loc
                    if srv and not discovered[ip].server:
                        discovered[ip].server = srv
            except socket.timeout:
                continue
            except Exception:
                break
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    if discovered:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(discovered))) as ex:
            list(ex.map(lambda d: fetch_upnp_xml_details(d, timeout=0.5), discovered.values()))

    return discovered


def probe_upnp_unicast(ip: str, timeout: float = 0.25) -> Optional[UpnpDeviceInfo]:
    """
    Sondagem unicast rápida SSDP na porta UDP 1900 de um host específico.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_msearch_packet(st="upnp:rootdevice", mx=1), (ip, SSDP_PORT))
        data, _ = sock.recvfrom(4096)
        text = data.decode("utf-8", errors="ignore")
        hdrs = parse_ssdp_headers(text)
        dev = UpnpDeviceInfo(
            ip=ip,
            location=hdrs.get("location", ""),
            server=hdrs.get("server", ""),
            st=hdrs.get("st", ""),
            usn=hdrs.get("usn", ""),
        )
        if dev.location:
            fetch_upnp_xml_details(dev, timeout=0.45)
        if dev.format_summary():
            return dev
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return None
