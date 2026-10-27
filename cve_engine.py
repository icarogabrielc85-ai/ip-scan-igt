#!/usr/bin/env python3
"""
Motor de Correlação de Vulnerabilidades (CVEs) com Base SQLite Local para o IP Scan IGT.
Cruza banners HTTP/SSH/SSL/SNMP, modelos ONVIF, portas abertas e versões extraídas pelo
parser regex do Nmap com um banco SQLite leve e curado de vulnerabilidades conhecidas (CVEs),
destacando dispositivos em risco na interface e oferecendo recomendações de mitigação.
"""
import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


CVE_DB_PATH = os.path.expanduser("~/.config/linux-ipscan/cve_knowledge.db")


@dataclass
class VulnerabilityMatch:
    cve_id: str
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW
    cvss: float
    product: str
    detected_version: str
    port: int
    title: str
    description: str
    remediation: str

    def badge_text(self) -> str:
        return f"{self.cve_id} ({self.severity} • CVSS {self.cvss:.1f})"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss": self.cvss,
            "product": self.product,
            "detected_version": self.detected_version,
            "port": self.port,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
        }


# Catálogo curado de vulnerabilidades conhecidas (CVEs) para ativos de rede local,
# servidores, roteadores, câmeras IP e protocolos legados.
# Campos: (cve_id, product_key, version_regex, min_ver, max_ver, port_hint, severity, cvss, title, description, remediation)
CURATED_CVE_RULES = [
    # --- OpenSSH ---
    (
        "CVE-2024-6387",
        "openssh",
        r"openssh[_/\-\s]*([0-9]+\.[0-9]+(?:p[0-9]+)?)",
        "8.5",
        "9.7",
        22,
        "CRITICAL",
        8.1,
        "OpenSSH RegreSSHion (Race Condition no sshd)",
        "Condição de corrida no manipulador de sinais (SIGALRM) do servidor OpenSSH em sistemas baseados em glibc.",
        "Atualizar o pacote openssh-server para a versão 9.8p1 ou aplicar o patch de segurança da distribuição Linux.",
    ),
    (
        "CVE-2023-38408",
        "openssh",
        r"openssh[_/\-\s]*([0-9]+\.[0-9]+(?:p[0-9]+)?)",
        "5.5",
        "9.3",
        22,
        "HIGH",
        7.5,
        "OpenSSH PKCS#11 Forwarded Agent Vulnerability",
        "Versões do OpenSSH anteriores à 9.3p2 possuem vulnerabilidade no suporte PKCS#11 do ssh-agent.",
        "Atualizar o OpenSSH para 9.3p2+ e desabilitar ForwardAgent quando não utilizado.",
    ),
    (
        "CVE-2020-15778",
        "openssh",
        r"openssh[_/\-\s]*([0-9]+\.[0-9]+(?:p[0-9]+)?)",
        "1.0",
        "8.3",
        22,
        "HIGH",
        7.8,
        "OpenSSH Legacy SCP Argument Injection",
        "Versão legada do OpenSSH vulnerável a injeção de argumentos no utilitário scp.",
        "Atualizar o servidor OpenSSH para versão moderna (9.x) e migrar transferências para SFTP.",
    ),
    # --- Dropbear SSH (Roteadores / Embarcados / Câmeras) ---
    (
        "CVE-2023-48795",
        "dropbear",
        r"dropbear[_/\-\s]*([0-9]{4}\.[0-9]+|[0-9]+\.[0-9]+)",
        "0.1",
        "2022.83",
        22,
        "MEDIUM",
        5.9,
        "Terrapin SSH Prefix Truncation Attack (Dropbear)",
        "Implementação SSH embarcada vulnerável ao truncamento de prefixo no handshake de canal.",
        "Atualizar o firmware do equipamento embarcado / roteador para Dropbear 2024.84 ou superior.",
    ),
    # --- Apache HTTP Server ---
    (
        "CVE-2021-41773",
        "apache",
        r"apache(?:\s+httpd)?(?:/|\s+)([0-9]+\.[0-9]+\.[0-9]+)",
        "2.4.49",
        "2.4.50",
        80,
        "CRITICAL",
        9.8,
        "Apache HTTP Server Path Traversal (2.4.49/2.4.50)",
        "Falha crítica de normalização de caminho no Apache HTTP Server 2.4.49 e 2.4.50 permitindo leitura de arquivos fora da raiz.",
        "Atualizar imediatamente o Apache HTTP Server para 2.4.51 ou superior.",
    ),
    (
        "CVE-2024-38476",
        "apache",
        r"apache(?:\s+httpd)?(?:/|\s+)([0-9]+\.[0-9]+\.[0-9]+)",
        "2.4.0",
        "2.4.59",
        80,
        "HIGH",
        7.5,
        "Apache HTTP Server Backend Output Handling Flaw",
        "Versões do Apache HTTP Server até 2.4.59 podem expor informações sensíveis ou sofrer manipulação de cabeçalhos em módulos de proxy/backend.",
        "Atualizar o Apache HTTP Server para a versão 2.4.60 ou superior.",
    ),
    # --- Nginx ---
    (
        "CVE-2021-23017",
        "nginx",
        r"nginx(?:/|\s+)([0-9]+\.[0-9]+\.[0-9]+)",
        "0.6.18",
        "1.20.0",
        80,
        "HIGH",
        7.7,
        "Nginx DNS Resolver Off-by-One Heap Write",
        "Vulnerabilidade de escrita fora dos limites de memória (off-by-one) no resolvedor DNS interno do Nginx antes de 1.20.1 / 1.21.0.",
        "Atualizar o servidor Nginx para 1.20.1+, 1.24.x ou 1.26.x.",
    ),
    (
        "CVE-2022-41741",
        "nginx",
        r"nginx(?:/|\s+)([0-9]+\.[0-9]+\.[0-9]+)",
        "1.1.3",
        "1.22.0",
        80,
        "HIGH",
        7.0,
        "Nginx ngx_http_mp4_module Memory Corruption",
        "Corrupção de memória no processamento de arquivos de mídia em versões do Nginx anteriores a 1.22.1 / 1.23.2.",
        "Atualizar o Nginx para a versão estável mais recente (1.24+ / 1.26+).",
    ),
    # --- Microsoft IIS ---
    (
        "CVE-2022-21907",
        "iis",
        r"(?:microsoft-iis|iis)(?:\s+httpd)?(?:/|\s+)([0-9]+\.[0-9]+)",
        "6.0",
        "10.0",
        80,
        "CRITICAL",
        9.8,
        "HTTP Protocol Stack (http.sys) Vulnerability em Microsoft IIS",
        "Servidor Microsoft IIS detectado. Caso o Windows Server não possua as atualizações cumulativas recentes, o driver http.sys pode estar exposto.",
        "Verificar a instalação dos patches cumulativos do Windows Update para o HTTP.sys e desabilitar Trailer Support se não aplicável.",
    ),
    # --- Samba / SMB ---
    (
        "CVE-2021-44142",
        "samba",
        r"samba(?:\s+smbd)?(?:/|\s+)([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "3.0.0",
        "4.15.4",
        445,
        "CRITICAL",
        9.9,
        "Samba vfs_fruit Out-of-Bounds Heap Read/Write",
        "Vulnerabilidade crítica no módulo VFS fruit do Samba em versões anteriores a 4.13.17, 4.14.12 e 4.15.5.",
        "Atualizar o pacote Samba do servidor Linux e revisar módulos VFS habilitados no smb.conf.",
    ),
    # --- MikroTik RouterOS / Winbox ---
    (
        "CVE-2018-14847",
        "mikrotik",
        r"(?:mikrotik|routeros|winbox)(?:[_/\-\s]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?))?",
        "6.0",
        "6.42",
        8291,
        "CRITICAL",
        9.1,
        "MikroTik RouterOS Winbox Directory Traversal (Porta 8291)",
        "Serviço MikroTik Winbox (TCP 8291) exposto na rede. Versões antigas do RouterOS (<6.42.1) permitem leitura não autenticada de credenciais.",
        "Atualizar o RouterOS para v6.49+ ou v7.x e restringir o acesso à porta 8291 por lista de IPs confiáveis em /ip service.",
    ),
    # --- Hikvision Cameras / NVRs ---
    (
        "CVE-2021-36260",
        "hikvision",
        r"(?:hikvision|ds-2cd|dnvr|dvr-web)",
        "",
        "",
        80,
        "CRITICAL",
        9.8,
        "Auditoria de Firmware Hikvision Web Server (CVE-2021-36260)",
        "Dispositivo de vídeo Hikvision com interface Web ativa. Firmwares anteriores a 2021-09 possuem falha crítica de validação de mensagens HTTP.",
        "Verificar se o firmware da câmera/NVR Hikvision está atualizado (Build >= 210628) e isolar os equipamentos de CFTV em uma VLAN dedicada.",
    ),
    # --- Dahua / Intelbras OEM Cameras / NVRs ---
    (
        "CVE-2021-33044",
        "dahua",
        r"(?:dahua|nvr-3|mibo|vip-|dh-ipc)",
        "",
        "",
        80,
        "HIGH",
        8.8,
        "Auditoria de Autenticação Web em Câmera/NVR (CVE-2021-33044)",
        "Gravador NVR ou câmera IP com painel web exposto. Firmwares legados anteriores a 2021-10 são suscetíveis a bypass de autenticação no painel web.",
        "Garantir que o firmware do NVR/Câmera esteja na versão mais recente do fabricante e desativar acesso HTTP externo.",
    ),
    # --- vsftpd ---
    (
        "CVE-2011-2523",
        "vsftpd",
        r"vsftpd(?:/|\s+)([0-9]+\.[0-9]+\.[0-9]+)",
        "2.3.4",
        "2.3.4",
        21,
        "CRITICAL",
        9.8,
        "vsftpd 2.3.4 Compromised Source Package",
        "A versão específica 2.3.4 do servidor FTP vsftpd possui uma falha crítica conhecida.",
        "Atualizar imediatamente o pacote vsftpd para 3.0.3+ ou substituir por SFTP (OpenSSH).",
    ),
    # --- ProFTPD ---
    (
        "CVE-2019-12815",
        "proftpd",
        r"proftpd(?:/|\s+)([0-9]+\.[0-9]+\.[0-9]+)",
        "1.3.0",
        "1.3.6",
        21,
        "CRITICAL",
        9.8,
        "ProFTPD mod_copy Arbitrary File Copy",
        "Versões do ProFTPD até 1.3.6 possuem vulnerabilidade no módulo mod_copy permitindo cópia de arquivos sem autenticação.",
        "Atualizar o ProFTPD para 1.3.7+ e desabilitar o módulo mod_copy na configuração.",
    ),
    # --- Exposições de Protocolos Legados / Inseguros por Porta ---
    (
        "CVE-1999-0619",
        "port:23",
        r"",
        "",
        "",
        23,
        "HIGH",
        7.5,
        "Serviço Telnet Ativo em Texto Puro (Porta TCP 23)",
        "O protocolo Telnet transmite credenciais de administrador e comandos sem criptografia na rede local (suscetível a interceptação ARP/MITM).",
        "Desativar imediatamente o serviço Telnet (porta 23) no ativo e utilizar exclusivamente SSH (porta 22) com criptografia.",
    ),
    (
        "CVE-1999-0497",
        "port:21",
        r"",
        "",
        "",
        21,
        "MEDIUM",
        5.3,
        "Servidor FTP em Texto Puro Exposto (Porta TCP 21)",
        "O serviço FTP padrão na porta 21 trafega usuário, senha e arquivos sem criptografia TLS.",
        "Migrar para SFTP (porta 22) ou habilitar FTPS explícito (TLS) e desabilitar login anônimo.",
    ),
    (
        "CVE-1999-0517",
        "snmp:public",
        r"",
        "",
        "",
        161,
        "MEDIUM",
        5.8,
        "SNMPv1/v2c Ativo com Community Padrão 'public' (UDP 161)",
        "O equipamento respondeu a consultas SNMP utilizando a community string padrão 'public', expondo topologia, uptime e inventário de hardware.",
        "Alterar a community string SNMP padrão ou migrar para SNMPv3 com autenticação e criptografia (authPriv).",
    ),
    (
        "CVE-2019-0708",
        "port:3389",
        r"",
        "",
        "",
        3389,
        "MEDIUM",
        6.5,
        "Exposição Direta de Área de Trabalho Remota RDP (Porta TCP 3389)",
        "O serviço Microsoft RDP está exposto na rede. Sem Network Level Authentication (NLA) e patches atualizados, fica sujeito a força bruta e falhas críticas.",
        "Certificar-se de que a Autenticação no Nível da Rede (NLA) esteja obrigatória nas Propriedades do Sistema Windows e restringir por Firewall.",
    ),
]


def _parse_version_tuple(ver_str: str) -> Tuple[int, ...]:
    """Extrai números principais de uma string de versão (ex: '8.9p1' -> (8, 9, 1))."""
    if not ver_str:
        return ()
    nums = re.findall(r"\d+", ver_str)
    if not nums:
        return ()
    return tuple(int(n) for n in nums[:4])


def _version_in_range(detected: str, min_ver: str, max_ver: str) -> bool:
    """Verifica se a versão detectada está dentro do intervalo [min_ver, max_ver]."""
    if not min_ver and not max_ver:
        return True
    det_t = _parse_version_tuple(detected)
    if not det_t:
        return False
    min_t = _parse_version_tuple(min_ver)
    max_t = _parse_version_tuple(max_ver)
    # Normaliza comprimentos comparando apenas os prefixos relevantes
    if min_t:
        cmp_len = max(len(det_t), len(min_t))
        d_pad = det_t + (0,) * (cmp_len - len(det_t))
        min_pad = min_t + (0,) * (cmp_len - len(min_t))
        if d_pad < min_pad:
            return False
    if max_t:
        cmp_len = max(len(det_t), len(max_t))
        d_pad = det_t + (0,) * (cmp_len - len(det_t))
        max_pad = max_t + (0,) * (cmp_len - len(max_t))
        if d_pad > max_pad:
            return False
    return True


class CveDatabase:
    """Gerencia o banco de dados SQLite local de vulnerabilidades e executa a correlação."""

    def __init__(self, db_path: str = CVE_DB_PATH):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._rules_cache: Optional[List[Dict[str, Any]]] = None
        self._ensure_database()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
        except Exception:
            conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn = conn
        return conn

    def _ensure_database(self):
        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_catalog (
                    cve_id TEXT PRIMARY KEY,
                    product_key TEXT NOT NULL,
                    version_regex TEXT,
                    min_ver TEXT,
                    max_ver TEXT,
                    port_hint INTEGER,
                    severity TEXT NOT NULL,
                    cvss REAL NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    remediation TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_catalog(product_key)
                """
            )
            cur.executemany(
                """
                INSERT OR REPLACE INTO cve_catalog (
                    cve_id, product_key, version_regex, min_ver, max_ver,
                    port_hint, severity, cvss, title, description, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                CURATED_CVE_RULES,
            )
            conn.commit()
            self._rules_cache = None

    def get_all_rules(self) -> List[Dict[str, Any]]:
        if self._rules_cache is not None:
            return self._rules_cache
        with self._lock:
            if self._rules_cache is not None:
                return self._rules_cache
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT cve_id, product_key, version_regex, min_ver, max_ver,
                       port_hint, severity, cvss, title, description, remediation
                FROM cve_catalog
                ORDER BY cvss DESC
                """
            )
            rows = cur.fetchall()
            rules: List[Dict[str, Any]] = []
            for r in rows:
                v_regex = r[2] or ""
                compiled_re = re.compile(v_regex, re.IGNORECASE) if v_regex else None
                rules.append({
                    "cve_id": r[0],
                    "product_key": r[1],
                    "version_regex": v_regex,
                    "compiled_regex": compiled_re,
                    "min_ver": r[3] or "",
                    "max_ver": r[4] or "",
                    "port_hint": int(r[5] or 0),
                    "severity": r[6],
                    "cvss": float(r[7] or 0.0),
                    "title": r[8],
                    "description": r[9],
                    "remediation": r[10],
                })
            self._rules_cache = rules
            return rules

    def correlate_host(
        self,
        open_ports: List[int],
        http_info: str = "",
        ssh_banner: str = "",
        ssl_info: str = "",
        snmp_info: str = "",
        vendor: str = "",
        onvif_model: str = "",
        nmap_services: Optional[Dict[int, str]] = None,
    ) -> List[VulnerabilityMatch]:
        """
        Cruza todos os banners, portas abertas, dados SNMP e versões do Nmap de um host
        com o catálogo SQLite de CVEs, retornando a lista ordenada por criticidade (CVSS).
        """
        matches: Dict[str, VulnerabilityMatch] = {}
        nmap_services = nmap_services or {}
        ports_set = set(open_ports or []) | set(nmap_services.keys())

        # Combina todas as fontes de texto/banners para inspeção de versão
        banner_blobs = [
            http_info or "",
            ssh_banner or "",
            ssl_info or "",
            snmp_info or "",
            vendor or "",
            onvif_model or "",
        ]
        for p, svc_txt in nmap_services.items():
            banner_blobs.append(f"port:{p} {svc_txt}")

        combined_text = " | ".join(b for b in banner_blobs if b)
        combined_lower = combined_text.lower()

        rules = self.get_all_rules()

        for rule in rules:
            cve_id = rule["cve_id"]
            pkey = rule["product_key"].lower()
            v_regex = rule["version_regex"]
            min_v = rule["min_ver"]
            max_v = rule["max_ver"]
            port_hint = rule["port_hint"]

            # 1. Regras baseadas em exposição direta de porta (ex: port:23, port:21, port:3389)
            if pkey.startswith("port:"):
                req_port = int(pkey.split(":")[1])
                if req_port in ports_set:
                    matches[cve_id] = VulnerabilityMatch(
                        cve_id=cve_id,
                        severity=rule["severity"],
                        cvss=rule["cvss"],
                        product=f"TCP/{req_port}",
                        detected_version="Ativo",
                        port=req_port,
                        title=rule["title"],
                        description=rule["description"],
                        remediation=rule["remediation"],
                    )
                continue

            # 2. Regra baseada em SNMP community 'public'
            if pkey == "snmp:public":
                if snmp_info:
                    matches[cve_id] = VulnerabilityMatch(
                        cve_id=cve_id,
                        severity=rule["severity"],
                        cvss=rule["cvss"],
                        product="SNMPv2c Agent",
                        detected_version="Community 'public'",
                        port=161,
                        title=rule["title"],
                        description=rule["description"],
                        remediation=rule["remediation"],
                    )
                continue

            # 3. Regras de produto + regex de versão (OpenSSH, Apache, Nginx, IIS, Samba, MikroTik, etc.)
            if v_regex:
                compiled_re = rule.get("compiled_regex")
                m = compiled_re.search(combined_text) if compiled_re else re.search(v_regex, combined_text, re.IGNORECASE)
                if not m:
                    # Caso especial: porta 8291 aberta identifica MikroTik Winbox mesmo sem banner textual
                    if pkey == "mikrotik" and 8291 in ports_set:
                        matches[cve_id] = VulnerabilityMatch(
                            cve_id=cve_id,
                            severity=rule["severity"],
                            cvss=rule["cvss"],
                            product="MikroTik Winbox",
                            detected_version="Porta 8291 Aberta",
                            port=8291,
                            title=rule["title"],
                            description=rule["description"],
                            remediation=rule["remediation"],
                        )
                    continue

                detected_ver = m.group(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else ""

                # Se a regra exige intervalo de versão, verifica se está na faixa vulnerável
                if min_v or max_v:
                    if not detected_ver:
                        # Para MikroTik sem versão explícita, ainda alerta se a porta 8291 estiver aberta
                        if pkey == "mikrotik" and 8291 in ports_set:
                            detected_ver = "Serviço Ativo"
                        else:
                            continue
                    elif not _version_in_range(detected_ver, min_v, max_v):
                        continue
                else:
                    # Regra de família de hardware/firmware (ex: Hikvision / Dahua com web aberta)
                    if port_hint and port_hint not in ports_set and 80 not in ports_set and 443 not in ports_set and 8080 not in ports_set:
                        continue
                    if not detected_ver:
                        detected_ver = onvif_model or vendor or pkey.capitalize()

                matches[cve_id] = VulnerabilityMatch(
                    cve_id=cve_id,
                    severity=rule["severity"],
                    cvss=rule["cvss"],
                    product=pkey.upper() if len(pkey) <= 4 else pkey.capitalize(),
                    detected_version=detected_ver,
                    port=port_hint if port_hint in ports_set else (next(iter(ports_set), port_hint)),
                    title=rule["title"],
                    description=rule["description"],
                    remediation=rule["remediation"],
                )

        sorted_matches = sorted(matches.values(), key=lambda x: x.cvss, reverse=True)
        return sorted_matches


# Instância singleton global para consultas rápidas
CVE_DB = CveDatabase()


def compute_risk_summary(vulns: List[VulnerabilityMatch]) -> Tuple[str, float, str]:
    """
    Retorna (risk_level, max_cvss, badge_label) para uma lista de vulnerabilidades.
    risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
    """
    if not vulns:
        return "NONE", 0.0, ""
    max_cvss = max(v.cvss for v in vulns)
    severities = {v.severity for v in vulns}
    count = len(vulns)
    if "CRITICAL" in severities or max_cvss >= 9.0:
        lvl = "CRITICAL"
        badge = f"🚨 CRÍTICO ({count} CVE{'s' if count > 1 else ''} • CVSS {max_cvss:.1f})"
    elif "HIGH" in severities or max_cvss >= 7.0:
        lvl = "HIGH"
        badge = f"⚠️ ALTO RISCO ({count} CVE{'s' if count > 1 else ''} • CVSS {max_cvss:.1f})"
    elif "MEDIUM" in severities or max_cvss >= 4.0:
        lvl = "MEDIUM"
        badge = f"🛡️ MÉDIO ({count} CVE{'s' if count > 1 else ''} • CVSS {max_cvss:.1f})"
    else:
        lvl = "LOW"
        badge = f"ℹ️ BAIXO ({count} CVE{'s' if count > 1 else ''})"
    return lvl, max_cvss, badge
