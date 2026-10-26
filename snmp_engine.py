#!/usr/bin/env python3
"""
Motor de Auditoria SNMP (UDP 161) em Python Puro para o IP Scan IGT.
Implementa codificação/decodificação ASN.1 BER (SNMPv2c / SNMPv1) via socket UDP
sem necessidade de bibliotecas externas pesadas (como pysnmp), garantindo
compatibilidade total com compilação PyInstaller (.deb e .exe).

Extrai dados de ativos de infraestrutura:
- Roteadores e Switches (sysDescr, sysName, sysUpTime, sysLocation, número de portas/interfaces)
- Impressoras de Rede (Printer-MIB: contador de páginas impressas, nível de toner/suprimentos)
- Servidores e Nobreaks / UPS
"""
import random
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# OIDs Padrão MIB-II (RFC 1213) e Printer-MIB (RFC 3805)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"       # Descrição de hardware/SO do equipamento
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"   # Enterprise OID do fabricante
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"      # Tempo ligado (TimeTicks: centésimos de segundo)
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"     # Contato do administrador
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"        # Hostname administrativo configurado
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"    # Localização física do ativo
OID_IF_NUMBER = "1.3.6.1.2.1.2.1.0"       # Total de interfaces de rede / portas de switch

# OIDs de Impressoras (Printer-MIB / Host-Resources)
OID_PRT_PAGE_COUNT = "1.3.6.1.2.1.43.10.2.1.4.1.1"    # Contador vitalício de páginas impressas
OID_PRT_SUPPLY_DESC = "1.3.6.1.2.1.43.11.1.1.6.1.1"   # Nome do suprimento / toner principal
OID_PRT_SUPPLY_MAX = "1.3.6.1.2.1.43.11.1.1.8.1.1"    # Capacidade máxima do toner
OID_PRT_SUPPLY_LVL = "1.3.6.1.2.1.43.11.1.1.9.1.1"    # Nível atual do toner
OID_PRT_SERIAL_NO = "1.3.6.1.2.1.43.5.1.1.17.1"       # Número de série da impressora


@dataclass
class SnmpAuditResult:
    enabled: bool = False
    community: str = "public"
    sys_descr: str = ""
    sys_name: str = ""
    sys_location: str = ""
    sys_contact: str = ""
    uptime_ticks: int = 0
    uptime_str: str = ""
    if_count: int = 0
    printer_pages: int = -1
    toner_name: str = ""
    toner_percent: int = -1
    printer_serial: str = ""
    raw_oids: Dict[str, str] = field(default_factory=dict)

    def format_summary(self) -> str:
        """Retorna um resumo compacto para exibição na árvore e nos detalhes."""
        if not self.enabled:
            return ""
        parts = []
        if self.sys_name:
            parts.append(self.sys_name)
        if self.sys_descr:
            short_descr = self.sys_descr.splitlines()[0].strip()
            if len(short_descr) > 65:
                short_descr = short_descr[:62] + "..."
            parts.append(short_descr)
        if self.uptime_str:
            parts.append(f"Uptime: {self.uptime_str}")
        if self.if_count > 0:
            parts.append(f"Portas/Ifaces: {self.if_count}")
        if self.toner_percent >= 0:
            parts.append(f"Toner: {self.toner_percent}%")
        if self.printer_pages >= 0:
            parts.append(f"Páginas: {self.printer_pages}")
        if self.sys_location:
            parts.append(f"Local: {self.sys_location}")
        return " • ".join(parts)

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "community": self.community,
            "sys_descr": self.sys_descr,
            "sys_name": self.sys_name,
            "sys_location": self.sys_location,
            "sys_contact": self.sys_contact,
            "uptime_ticks": self.uptime_ticks,
            "uptime_str": self.uptime_str,
            "if_count": self.if_count,
            "printer_pages": self.printer_pages,
            "toner_name": self.toner_name,
            "toner_percent": self.toner_percent,
            "printer_serial": self.printer_serial,
        }


def format_timeticks(ticks: int) -> str:
    """Converte TimeTicks SNMP (1/100 de segundo) para formato legível (ex: 14d 06h 22m)."""
    if ticks <= 0:
        return ""
    total_seconds = ticks // 100
    days = total_seconds // 86400
    rem = total_seconds % 86400
    hours = rem // 3600
    minutes = (rem % 3600) // 60
    seconds = rem % 60
    if days > 0:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours > 0:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    return f"{minutes}m {seconds}s"


def _encode_ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    octets = []
    temp = length
    while temp > 0:
        octets.insert(0, temp & 0xFF)
        temp >>= 8
    return bytes([0x80 | len(octets)] + octets)


def _encode_ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_ber_length(len(value)) + value


def _encode_ber_integer(val: int) -> bytes:
    if val == 0:
        return _encode_ber_tlv(0x02, b"\x00")
    octets = []
    temp = val
    while temp > 0:
        octets.insert(0, temp & 0xFF)
        temp >>= 8
    if octets[0] & 0x80:
        octets.insert(0, 0x00)
    return _encode_ber_tlv(0x02, bytes(octets))


def _encode_ber_string(s: str) -> bytes:
    return _encode_ber_tlv(0x04, s.encode("utf-8", errors="ignore"))


def _encode_ber_null() -> bytes:
    return b"\x05\x00"


def _encode_ber_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.strip(".").split(".") if x]
    if len(parts) < 2:
        parts = [1, 3]
    encoded = [parts[0] * 40 + parts[1]]
    for sub_id in parts[2:]:
        if sub_id == 0:
            encoded.append(0)
        else:
            sub_bytes = []
            temp = sub_id
            while temp > 0:
                sub_bytes.insert(0, temp & 0x7F)
                temp >>= 7
            for i in range(len(sub_bytes) - 1):
                sub_bytes[i] |= 0x80
            encoded.extend(sub_bytes)
    return _encode_ber_tlv(0x06, bytes(encoded))


def build_snmp_get_packet(oids: List[str], community: str = "public", version: int = 1, req_id: Optional[int] = None) -> bytes:
    """
    Constrói um pacote SNMP GetRequest (PDU 0xA0) codificado em ASN.1 BER.
    version=1 corresponde ao SNMPv2c (version=0 é SNMPv1).
    """
    if req_id is None:
        req_id = random.randint(10000, 999999)

    varbinds = b""
    for oid in oids:
        vb = _encode_ber_oid(oid) + _encode_ber_null()
        varbinds += _encode_ber_tlv(0x30, vb)

    varbind_list = _encode_ber_tlv(0x30, varbinds)
    pdu_body = (
        _encode_ber_integer(req_id)
        + _encode_ber_integer(0)  # error-status = 0
        + _encode_ber_integer(0)  # error-index = 0
        + varbind_list
    )
    get_pdu = _encode_ber_tlv(0xA0, pdu_body)

    msg_body = (
        _encode_ber_integer(version)
        + _encode_ber_string(community)
        + get_pdu
    )
    return _encode_ber_tlv(0x30, msg_body)


def _decode_ber_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    offset += 1
    if not (first & 0x80):
        return first, offset
    num_octets = first & 0x7F
    if num_octets == 0 or offset + num_octets > len(data):
        return 0, len(data)
    length = 0
    for _ in range(num_octets):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def _decode_ber_oid(val_bytes: bytes) -> str:
    if not val_bytes:
        return ""
    first = val_bytes[0]
    oids = [str(first // 40), str(first % 40)]
    sub_id = 0
    for b in val_bytes[1:]:
        sub_id = (sub_id << 7) | (b & 0x7F)
        if not (b & 0x80):
            oids.append(str(sub_id))
            sub_id = 0
    return ".".join(oids)


def _decode_ber_int(val_bytes: bytes) -> int:
    if not val_bytes:
        return 0
    val = 0
    for b in val_bytes:
        val = (val << 8) | b
    # Handle signed negative if MSB set for standard INTEGER (0x02)
    if val_bytes[0] & 0x80:
        val -= 1 << (8 * len(val_bytes))
    return val


def _decode_ber_uint(val_bytes: bytes) -> int:
    if not val_bytes:
        return 0
    val = 0
    for b in val_bytes:
        val = (val << 8) | b
    return val


def parse_snmp_response(data: bytes) -> Dict[str, object]:
    """
    Decodifica um pacote SNMP GetResponse (PDU 0xA2) e retorna um dicionário {oid: valor}.
    Ignora valores de exceção SNMPv2c (noSuchObject=0x80, noSuchInstance=0x81).
    """
    results: Dict[str, object] = {}
    if not data or len(data) < 10 or data[0] != 0x30:
        return results

    try:
        seq_len, pos = _decode_ber_length(data, 1)
        end_msg = min(len(data), pos + seq_len)

        # 1. version (INTEGER 0x02)
        if pos >= end_msg or data[pos] != 0x02:
            return results
        v_len, pos = _decode_ber_length(data, pos + 1)
        pos += v_len

        # 2. community (OCTET STRING 0x04)
        if pos >= end_msg or data[pos] != 0x04:
            return results
        c_len, pos = _decode_ber_length(data, pos + 1)
        pos += c_len

        # 3. GetResponse-PDU (0xA2)
        if pos >= end_msg or data[pos] != 0xA2:
            return results
        pdu_len, pos = _decode_ber_length(data, pos + 1)
        end_pdu = min(end_msg, pos + pdu_len)

        # request-id, error-status, error-index
        for _ in range(3):
            if pos >= end_pdu or data[pos] != 0x02:
                return results
            i_len, pos = _decode_ber_length(data, pos + 1)
            pos += i_len

        # VarBindList (SEQUENCE 0x30)
        if pos >= end_pdu or data[pos] != 0x30:
            return results
        vbl_len, pos = _decode_ber_length(data, pos + 1)
        end_vbl = min(end_pdu, pos + vbl_len)

        while pos < end_vbl:
            if data[pos] != 0x30:
                break
            vb_len, pos = _decode_ber_length(data, pos + 1)
            end_vb = min(end_vbl, pos + vb_len)

            # OID (0x06)
            if pos >= end_vb or data[pos] != 0x06:
                pos = end_vb
                continue
            oid_len, pos = _decode_ber_length(data, pos + 1)
            oid_str = _decode_ber_oid(data[pos : pos + oid_len])
            pos += oid_len

            if pos >= end_vb:
                break

            val_tag = data[pos]
            val_len, pos = _decode_ber_length(data, pos + 1)
            val_bytes = data[pos : pos + val_len]
            pos = end_vb

            # Decode value according to ASN.1 / SMI tag
            if val_tag in (0x05, 0x80, 0x81, 0x82):
                # NULL, noSuchObject, noSuchInstance, endOfMibView
                continue
            elif val_tag == 0x04:
                # OCTET STRING
                text = val_bytes.decode("utf-8", errors="replace").strip("\x00").strip()
                results[oid_str] = text
            elif val_tag == 0x02:
                # INTEGER
                results[oid_str] = _decode_ber_int(val_bytes)
            elif val_tag in (0x41, 0x42, 0x43):
                # Counter32 (0x41), Gauge32 (0x42), TimeTicks (0x43)
                results[oid_str] = _decode_ber_uint(val_bytes)
            elif val_tag == 0x06:
                # OBJECT IDENTIFIER
                results[oid_str] = _decode_ber_oid(val_bytes)
            elif val_tag == 0x40 and len(val_bytes) == 4:
                # IpAddress
                results[oid_str] = ".".join(str(b) for b in val_bytes)
    except Exception:
        pass

    return results


def probe_snmp(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 0.35,
    include_printer_mib: bool = True,
) -> SnmpAuditResult:
    """
    Sonda o ativo na porta UDP 161 via SNMPv2c (com fallback para SNMPv1)
    extraindo informações de sistema, uptime, número de interfaces e suprimentos de impressora.
    """
    audit = SnmpAuditResult(community=community)
    base_oids = [
        OID_SYS_DESCR,
        OID_SYS_UPTIME,
        OID_SYS_NAME,
        OID_SYS_LOCATION,
        OID_IF_NUMBER,
    ]

    resp_map: Dict[str, object] = {}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            # 1. Try SNMPv2c (version=1)
            pkt_v2 = build_snmp_get_packet(base_oids, community=community, version=1)
            sock.sendto(pkt_v2, (ip, port))
            raw_resp, _ = sock.recvfrom(4096)
            resp_map = parse_snmp_response(raw_resp)

            # Fallback to SNMPv1 (version=0) if empty
            if not resp_map:
                pkt_v1 = build_snmp_get_packet(base_oids, community=community, version=0)
                sock.sendto(pkt_v1, (ip, port))
                raw_resp, _ = sock.recvfrom(4096)
                resp_map = parse_snmp_response(raw_resp)

            if not resp_map:
                return audit

            audit.enabled = True
            audit.sys_descr = str(resp_map.get(OID_SYS_DESCR, "") or "").strip()
            audit.sys_name = str(resp_map.get(OID_SYS_NAME, "") or "").strip()
            audit.sys_location = str(resp_map.get(OID_SYS_LOCATION, "") or "").strip()

            ut = resp_map.get(OID_SYS_UPTIME, 0)
            if isinstance(ut, int) and ut > 0:
                audit.uptime_ticks = ut
                audit.uptime_str = format_timeticks(ut)

            ifc = resp_map.get(OID_IF_NUMBER, 0)
            if isinstance(ifc, int) and ifc > 0:
                audit.if_count = ifc

            for k, v in resp_map.items():
                audit.raw_oids[k] = str(v)

            # Se parecer impressora ou se solicitado, consulta Printer-MIB rapidamente
            descr_low = (audit.sys_descr + " " + audit.sys_name).lower()
            is_printer_like = any(
                kw in descr_low
                for kw in ["printer", "laserjet", "officejet", "deskjet", "epson", "brother", "ricoh", "lexmark", "kyocera", "zebra", "canon", "xerox", "samsung"]
            )
            if include_printer_mib and is_printer_like:
                prt_oids = [
                    OID_PRT_PAGE_COUNT,
                    OID_PRT_SUPPLY_DESC,
                    OID_PRT_SUPPLY_MAX,
                    OID_PRT_SUPPLY_LVL,
                ]
                pkt_prt = build_snmp_get_packet(prt_oids, community=community, version=1)
                sock.sendto(pkt_prt, (ip, port))
                try:
                    raw_prt, _ = sock.recvfrom(4096)
                    prt_map = parse_snmp_response(raw_prt)
                    pages = prt_map.get(OID_PRT_PAGE_COUNT)
                    if isinstance(pages, int) and pages >= 0:
                        audit.printer_pages = pages
                    s_desc = prt_map.get(OID_PRT_SUPPLY_DESC)
                    if s_desc:
                        audit.toner_name = str(s_desc).strip()
                    s_max = prt_map.get(OID_PRT_SUPPLY_MAX)
                    s_lvl = prt_map.get(OID_PRT_SUPPLY_LVL)
                    if isinstance(s_max, int) and isinstance(s_lvl, int) and s_max > 0 and s_lvl >= 0:
                        audit.toner_percent = min(100, max(0, int((s_lvl * 100) / s_max)))
                    for k, v in prt_map.items():
                        audit.raw_oids[k] = str(v)
                except Exception:
                    pass
    except Exception:
        pass

    return audit
