#!/usr/bin/env python3
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from typing import Dict, List, Optional, Tuple

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"

WS_DISCOVERY_PROBE = f"""<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope" xmlns:dn="http://www.onvif.org/ver10/network/wsdl" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <Header>
    <wsa:MessageID>uuid:{uuid.uuid4()}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
  </Header>
  <Body>
    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <Types>dn:NetworkVideoTransmitter</Types>
    </Probe>
  </Body>
</Envelope>""".encode("utf-8")


def parse_onvif_scopes(scopes_str: str) -> dict:
    parsed = {"types": [], "raw": scopes_str}
    for item in scopes_str.split():
        item = urllib.parse.unquote(item.strip())
        if "/hardware/" in item:
            parsed["hardware"] = item.split("/hardware/")[-1]
        elif "/name/" in item:
            parsed["name"] = item.split("/name/")[-1]
        elif "/type/" in item:
            t = item.split("/type/")[-1]
            if t not in parsed["types"]:
                parsed["types"].append(t)
        elif "/mac/" in item:
            parsed["mac"] = item.split("/mac/")[-1].upper()
        elif "/manufacturer/" in item:
            parsed["manufacturer"] = item.split("/manufacturer/")[-1]
        elif "/location/" in item:
            loc = item.split("/location/")[-1]
            if loc:
                parsed["location"] = loc

    # Determine general device category
    types_lower = [t.lower() for t in parsed["types"]]
    name_lower = (parsed.get("name", "") + " " + parsed.get("hardware", "")).lower()

    if "networkvideorecorder" in types_lower or "nvr" in types_lower or "nvr" in name_lower:
        parsed["category"] = "NVR"
    else:
        parsed["category"] = "Camera"

    return parsed


def discover_onvif_devices(timeout: float = 1.8) -> Dict[str, dict]:
    """
    Multicast WS-Discovery probe across the local network (239.255.255.250:3702).
    Discovers all ONVIF cameras and NVRs in 1-2 seconds.
    """
    devices: Dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)

    try:
        sock.sendto(WS_DISCOVERY_PROBE, ("239.255.255.250", 3702))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                remaining = max(0.05, deadline - time.time())
                sock.settimeout(remaining)
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")

                xaddrs = re.findall(r"<[^:]*:?XAddrs[^>]*>([^<]+)", text)
                scopes = re.findall(r"<[^:]*:?Scopes[^>]*>([^<]+)", text)

                xaddr_val = xaddrs[0].strip().split()[0] if xaddrs else f"http://{ip}:8899/onvif/device_service"
                scopes_val = scopes[0].strip() if scopes else ""

                info = parse_onvif_scopes(scopes_val)
                info["ip"] = ip
                info["xaddrs"] = xaddr_val
                info["rtsp_url"] = f"rtsp://{ip}:554/"

                devices[ip] = info
            except socket.timeout:
                break
            except Exception:
                pass
    except Exception:
        pass
    finally:
        sock.close()

    return devices


def get_onvif_stream_uri(ip: str, port: int = 8899, timeout: float = 2.0) -> Optional[str]:
    """
    Connects to ONVIF Media Service on the camera and retrieves the exact RTSP stream URI
    (including any required channel, profile token, or session parameters).
    """
    ports_to_try = [port] if port else [8899, 2443, 8000, 80]
    if 8899 not in ports_to_try:
        ports_to_try.append(8899)

    for p in ports_to_try:
        try:
            # 1. Query GetProfiles
            req_profiles = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body><GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/></s:Body>
</s:Envelope>"""
            req = urllib.request.Request(
                f"http://{ip}:{p}/onvif/Media",
                data=req_profiles.encode("utf-8"),
                headers={"Content-Type": "application/soap+xml; charset=utf-8"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                tokens = re.findall(r'token="([^"]+)"', text)
                token = tokens[0] if tokens else "000"

            # 2. Query GetStreamUri with profile token
            req_uri = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">
      <StreamSetup>
        <Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>
        <Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>RTSP</Protocol></Transport>
      </StreamSetup>
      <ProfileToken>{token}</ProfileToken>
    </GetStreamUri>
  </s:Body>
</s:Envelope>"""
            req2 = urllib.request.Request(
                f"http://{ip}:{p}/onvif/Media",
                data=req_uri.encode("utf-8"),
                headers={"Content-Type": "application/soap+xml; charset=utf-8"}
            )
            with urllib.request.urlopen(req2, timeout=timeout) as resp2:
                text2 = resp2.read().decode("utf-8", errors="ignore")
                uris = re.findall(r'<[^:]*:?Uri>([^<]+)', text2)
                if uris:
                    return uris[0].replace("&amp;", "&").strip()
        except Exception:
            pass
    return None


def probe_onvif_unicast(ip: str, timeout: float = 1.0) -> Optional[dict]:
    """
    Unicast probe to a single IP for ONVIF service.
    """
    # 1. Unicast UDP WS-Discovery to 3702
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        sock.sendto(WS_DISCOVERY_PROBE, (ip, 3702))
        data, _ = sock.recvfrom(65535)
        text = data.decode("utf-8", errors="ignore")
        xaddrs = re.findall(r"<[^:]*:?XAddrs[^>]*>([^<]+)", text)
        scopes = re.findall(r"<[^:]*:?Scopes[^>]*>([^<]+)", text)

        xaddr_val = xaddrs[0].strip().split()[0] if xaddrs else f"http://{ip}:8899/onvif/device_service"
        scopes_val = scopes[0].strip() if scopes else ""
        info = parse_onvif_scopes(scopes_val)
        info["ip"] = ip
        info["xaddrs"] = xaddr_val

        # Resolve exact working RTSP URI via ONVIF Media Service
        stream_uri = get_onvif_stream_uri(ip)
        info["rtsp_url"] = stream_uri or f"rtsp://{ip}:554/"
        return info
    except Exception:
        pass
    finally:
        sock.close()

    # 2. Check dedicated ONVIF TCP ports (exclude generic web port 80 to prevent false positives)
    for port in [8899, 2443, 8000]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    protocol = "https" if port in [443, 2443] else "http"
                    url = f"{protocol}://{ip}:{port}/onvif/device_service"
                    stream_uri = get_onvif_stream_uri(ip, port=port)
                    return {
                        "ip": ip,
                        "xaddrs": url,
                        "hardware": "Câmera ONVIF",
                        "name": f"ONVIF Port {port}",
                        "category": "Camera",
                        "rtsp_url": stream_uri or f"rtsp://{ip}:554/",
                    }
        except Exception:
            pass

    return None


def probe_rtsp(ip: str, port: int = 554, timeout: float = 1.2) -> Tuple[bool, str]:
    """
    Probes RTSP on port 554. Returns (is_open, banner).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return False, ""
            s.sendall(f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IPScanIGT\r\n\r\n".encode("utf-8"))
            data = s.recv(1024).decode("utf-8", errors="ignore")
            server_match = re.search(r"Server:\s*([^\r\n]+)", data, re.IGNORECASE)
            banner = server_match.group(1).strip() if server_match else "RTSP 1.0 Stream"
            return True, banner
    except Exception:
        return False, ""


def find_video_player(preferred: str = "auto") -> Tuple[Optional[str], str]:
    """
    Finds the best video player available on the operating system.
    Returns (executable_path, player_type) where player_type is 'ffplay' or 'vlc' or (None, '').
    """
    if IS_WINDOWS:
        ffplay_candidates = [
            shutil.which("ffplay"),
            shutil.which("ffplay.exe"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffplay.exe"),
            os.path.join(os.path.dirname(sys.executable), "ffplay.exe"),
        ]
        ffplay_path = None
        for c in ffplay_candidates:
            if c and os.path.exists(c):
                ffplay_path = c
                break

        vlc_candidates = [
            shutil.which("vlc"),
            shutil.which("vlc.exe"),
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "VideoLAN", "VLC", "vlc.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "VideoLAN", "VLC", "vlc.exe"),
            "C:\\Program Files\\VideoLAN\\VLC\\vlc.exe",
            "C:\\Program Files (x86)\\VideoLAN\\VLC\\vlc.exe",
        ]
        vlc_path = None
        for c in vlc_candidates:
            if c and os.path.exists(c):
                vlc_path = c
                break

        if preferred == "vlc" and vlc_path:
            return vlc_path, "vlc"
        if preferred == "ffplay" and ffplay_path:
            return ffplay_path, "ffplay"
        if ffplay_path:
            return ffplay_path, "ffplay"
        if vlc_path:
            return vlc_path, "vlc"
        return None, ""

    # Linux / macOS
    ffplay_path = None
    for c in [shutil.which("ffplay"), "/usr/bin/ffplay", "/usr/local/bin/ffplay"]:
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            ffplay_path = c
            break

    vlc_path = None
    for c in [shutil.which("vlc"), "/usr/bin/vlc", "/snap/bin/vlc", "/usr/local/bin/vlc"]:
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            vlc_path = c
            break

    if preferred == "vlc" and vlc_path:
        return vlc_path, "vlc"
    if preferred == "ffplay" and ffplay_path:
        return ffplay_path, "ffplay"
    if ffplay_path:
        return ffplay_path, "ffplay"
    if vlc_path:
        return vlc_path, "vlc"

    return None, ""


def launch_video_player(rtsp_url: str, title: str = "Câmera IP — IP Scan IGT") -> bool:
    """
    Launches ffplay or vlc with the given RTSP URL applying configured viewing resolution
    and latency parameters. Returns True if a player was launched.
    """
    try:
        from video_config_dialog import get_video_config, get_video_dimensions
        cfg = get_video_config()
        width, height = get_video_dimensions()
    except Exception:
        cfg = {}
        width, height = 800, 600

    preferred = cfg.get("player", "auto")
    transport = cfg.get("transport", "tcp")
    low_latency = cfg.get("low_latency", True)
    auto_exit = cfg.get("auto_exit", True)

    player_path, player_type = find_video_player(preferred=preferred)
    if not player_path:
        return False

    try:
        if player_type == "ffplay":
            cmd = [player_path]
            if transport in ["tcp", "udp"]:
                cmd += ["-rtsp_transport", transport]
            if low_latency:
                cmd += ["-fflags", "nobuffer", "-flags", "low_delay", "-framedrop", "-infbuf"]
            if auto_exit:
                cmd += ["-autoexit"]
            if width and height and width > 0 and height > 0:
                cmd += ["-x", str(width), "-y", str(height)]
            cmd += ["-window_title", title, rtsp_url]
        else:
            cmd = [player_path]
            if transport == "tcp":
                cmd += ["--rtsp-tcp"]
            if low_latency:
                cmd += ["--network-caching=300"]
            if width and height and width > 0 and height > 0:
                cmd += [f"--width={width}", f"--height={height}"]
            cmd += [rtsp_url]

        subprocess.Popen(cmd)
        return True
    except Exception as e:
        print("Error launching video player:", e)
        return False
