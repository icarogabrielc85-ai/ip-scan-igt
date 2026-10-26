#!/usr/bin/env python3
import os
import re
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import QThread, pyqtSignal
from cve_engine import CVE_DB, compute_risk_summary

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"


def get_nmap_path() -> Optional[str]:
    if IS_WINDOWS:
        p = shutil.which("nmap") or shutil.which("nmap.exe")
        if p:
            return p
        candidates = [
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Nmap", "nmap.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Nmap", "nmap.exe"),
            "C:\\Program Files (x86)\\Nmap\\nmap.exe",
            "C:\\Program Files\\Nmap\\nmap.exe",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    # Linux / Unix
    candidates = [
        os.path.expanduser("~/.local/bin/nmap"),
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
    ]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c
    return shutil.which("nmap")


def is_nmap_available() -> bool:
    return get_nmap_path() is not None


def parse_nmap_output(text: str, target: str = "") -> dict:
    result = {
        "ports": [],
        "all_ports": [],
        "open_ports_list": [],
        "closed_ports_list": [],
        "filtered_ports_list": [],
        "services": {},
        "os": "",
        "latency": "",
        "mac": "",
        "vendor": "",
        "device_diagnosis": "",
        "diagnosis_icon": "🖧",
        "vulnerabilities": [],
        "risk_level": "NONE",
        "max_cvss": 0.0,
        "risk_badge": "",
    }

    # Extract all ports: PORT STATE SERVICE VERSION
    port_regex = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([^\r\n\s]+)(?:[ \t]+([^\r\n]+))?$", re.MULTILINE)
    for match in port_regex.finditer(text):
        port_num = int(match.group(1))
        proto = match.group(2).upper()
        state = match.group(3).lower()
        service = match.group(4)
        version = (match.group(5) or "").strip()

        port_data = {
            "port": port_num,
            "proto": proto,
            "state": state,
            "service": service,
            "version": version,
        }
        result["all_ports"].append(port_data)

        if state == "open":
            result["open_ports_list"].append(port_num)
            svc_desc = f"{service} {version}".strip()
            result["services"][port_num] = svc_desc
            result["ports"].append(port_data)
        elif state == "closed":
            result["closed_ports_list"].append(port_num)
        elif state == "filtered":
            result["filtered_ports_list"].append(port_num)

    # MAC & Vendor
    mac_match = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\((.*?)\))?", text)
    if mac_match:
        result["mac"] = mac_match.group(1).upper()
        if mac_match.group(2):
            result["vendor"] = mac_match.group(2).strip()

    # Latency
    latency_match = re.search(r"Host is up \(([\d\.]+s) latency\)", text)
    if latency_match:
        result["latency"] = latency_match.group(1)

    # OS Guess
    os_match = re.search(r"(?:OS details|Service Info: OS|Running):\s*([^\r\n]+)", text)
    if os_match:
        result["os"] = os_match.group(1).strip()

    # Intelligent Human-Friendly Diagnosis
    open_p = set(result["open_ports_list"])
    services_str = " ".join(result["services"].values()).lower()
    tgt = target or "Dispositivo"

    if 554 in open_p or 8899 in open_p or 2443 in open_p:
        if 2443 in open_p or "nvr" in services_str:
            result["diagnosis_icon"] = "📹"
            result["device_diagnosis"] = f"Gravador NVR (ONVIF) identificado ({tgt}). Portas de vídeo RTSP (554) e gerenciamento ONVIF ativas."
        else:
            result["diagnosis_icon"] = "📹"
            result["device_diagnosis"] = f"Câmera de Segurança IP (ONVIF) identificada ({tgt}). Stream RTSP (554) pronto para reprodução no VLC."
    elif "tp-link" in services_str or (80 in open_p and "http" in services_str and ("tp-link" in text.lower() or "tplink" in text.lower())):
        result["diagnosis_icon"] = "📡"
        result["device_diagnosis"] = f"Equipamento de Rede / Roteador TP-Link ({tgt}). Apenas o painel web (porta 80) está aberto. Portas de vídeo e ONVIF estão fechadas (não é câmera)."
    elif 8006 in open_p:
        result["diagnosis_icon"] = "🖥️"
        result["device_diagnosis"] = f"Servidor de Virtualização Proxmox VE ({tgt}). Interface de controle na porta HTTPS 8006."
    elif 80 in open_p or 443 in open_p or 8080 in open_p or 8443 in open_p:
        result["diagnosis_icon"] = "🌐"
        result["device_diagnosis"] = f"Servidor Web / Painel de Administração ativo no host ({tgt}). Interface web pronta para acesso no navegador."
    elif 22 in open_p:
        result["diagnosis_icon"] = "🐧"
        result["device_diagnosis"] = f"Servidor Linux / Unix ({tgt}). Acesso remoto via terminal SSH ativo na porta 22."
    elif 445 in open_p or 3389 in open_p:
        result["diagnosis_icon"] = "💻"
        result["device_diagnosis"] = f"Sistema Windows ou servidor de arquivos SMB ({tgt}). Compartilhamento de rede ou Área de Trabalho Remota ativa."
    elif not open_p:
        result["diagnosis_icon"] = "🔒"
        result["device_diagnosis"] = f"Todas as portas testadas no host ({tgt}) responderam como FECHADAS ou FILTRADAS por firewall."
    else:
        result["diagnosis_icon"] = "🔌"
        result["device_diagnosis"] = f"Host online ({tgt}) com {len(open_p)} porta(s) aberta(s) identificada(s)."

    vulns = CVE_DB.correlate_host(
        open_ports=result["open_ports_list"],
        vendor=result["vendor"],
        nmap_services=result["services"],
    )
    result["vulnerabilities"] = vulns
    rlvl, mcvss, rbadge = compute_risk_summary(vulns)
    result["risk_level"] = rlvl
    result["max_cvss"] = mcvss
    result["risk_badge"] = rbadge
    if vulns:
        result["device_diagnosis"] += f" | ⚠️ Auditoria de Segurança: {len(vulns)} vulnerabilidade(s) conhecida(s) detectada(s) ({rbadge})."

    return result


class NmapScannerThread(QThread):
    line_output = pyqtSignal(str)
    scan_finished = pyqtSignal(str, dict, str)  # target, parsed_dict, raw_text
    scan_error = pyqtSignal(str)

    def __init__(self, target: str, scan_profile: str = "quick", custom_args: str = ""):
        super().__init__()
        self.target = target.strip()
        self.scan_profile = scan_profile
        self.custom_args = custom_args
        self._process: Optional[subprocess.Popen] = None
        self._is_stopped = False

    def stop(self):
        self._is_stopped = True
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=1.0)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass

    def build_command(self) -> List[str]:
        nmap = get_nmap_path() or "nmap"
        cmd = [nmap]

        if self.custom_args.strip():
            cmd.extend(self.custom_args.strip().split())
            cmd.append(self.target)
            return cmd

        if self.scan_profile == "quick":
            # Fast TCP connect scan (top 100 ports)
            cmd.extend(["-sT", "-F", "--min-rate", "300", "-T4", self.target])
        elif self.scan_profile == "services":
            # Version & service detection on popular ports + ONVIF/RTSP
            ports = "21,22,23,53,80,111,139,443,445,554,631,2443,3306,3389,3702,5060,5432,5900,8000,8006,8080,8291,8443,8899,9100"
            cmd.extend(["-sT", "-sV", "--version-light", "-p", ports, "-T4", self.target])
        elif self.scan_profile == "all_ports":
            # All 65,535 ports
            cmd.extend(["-sT", "-p-", "-T4", "--min-rate", "800", self.target])
        elif self.scan_profile == "onvif":
            # ONVIF / RTSP / Video surveillance scan
            cmd.extend(["-sT", "-sV", "--version-light", "-p", "80,554,1935,2020,2443,3702,8000,8080,8443,8899", "-T4", self.target])
        elif self.scan_profile == "vuln":
            # Vulnerability detection scripts
            cmd.extend(["-sT", "--script", "vuln,safe", "-p", "80,443,445,554,8006,8080", "-T4", self.target])
        else:
            cmd.extend(["-sT", "-F", self.target])

        return cmd

    def run(self):
        cmd = self.build_command()
        self.line_output.emit(f"==> Executando: {' '.join(cmd)}\n")

        env = os.environ.copy()
        if not IS_WINDOWS:
            nmap_lib = os.path.expanduser("~/.local/share/nmap/usr/lib/x86_64-linux-gnu")
            if os.path.exists(nmap_lib):
                env["LD_LIBRARY_PATH"] = f"{nmap_lib}:{env.get('LD_LIBRARY_PATH', '')}"
            nmap_dir = os.path.expanduser("~/.local/share/nmap/usr/share/nmap")
            if os.path.exists(nmap_dir):
                env["NMAPDIR"] = nmap_dir

        popen_kwargs = {}
        if IS_WINDOWS and hasattr(subprocess, "CREATE_NO_WINDOW"):
            popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        raw_output = []
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                **popen_kwargs,
            )

            for line in iter(self._process.stdout.readline, ""):
                if self._is_stopped:
                    break
                raw_output.append(line)
                self.line_output.emit(line)

            self._process.stdout.close()
            try:
                self._process.wait(timeout=2.0)
            except Exception:
                pass

            if self._is_stopped:
                return

            full_text = "".join(raw_output)
            parsed = parse_nmap_output(full_text, self.target)
            self.scan_finished.emit(self.target, parsed, full_text)

        except Exception as e:
            self.scan_error.emit(f"Erro ao executar Nmap: {e}")
