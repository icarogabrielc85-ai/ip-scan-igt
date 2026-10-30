#!/usr/bin/env python3
"""
Suíte de Testes Automatizados para o Identificador de Porta de Switch (LLDP / CDP / SNMP)
Valida a decodificação de frames LLDP/CDP, extração de portas, estimativa de capacidade
e renderização gráfica do widget do painel do switch.
"""
import os
import struct
import sys

# Garante que o diretório raiz do projeto esteja no sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication

from lldp_dialog import LLDPSwitchDialog
from lldp_engine import (
    LLDPPortInfo,
    check_sniffer_binary_cap,
    estimate_total_ports,
    extract_port_number,
    find_l2_sniffer_binary,
    get_demo_preset,
    get_l2_sniffer_candidates,
    parse_cdp_packet,
    parse_lldp_frame,
)
from switch_visual_widget import SwitchFrontPanelWidget


def build_synthetic_lldp_frame(
    chassis_mac: str = "00:11:22:33:44:55",
    port_id: str = "GigabitEthernet1/0/12",
    sys_name: str = "SW-TEST-CORE",
    sys_descr: str = "Cisco Catalyst 2960X-24TD-L",
    mgmt_ip: str = "192.168.1.254",
    vlan_id: int = 10,
) -> bytes:
    """Constrói um pacote bruto LLDP válido para validação dos testes."""
    # Ethernet Header (14 bytes): Dst=01:80:C2:00:00:0E, Src=00:11:22:33:44:55, Type=0x88CC
    dst_mac_bytes = bytes.fromhex("0180c200000e")
    src_mac_bytes = bytes.fromhex(chassis_mac.replace(":", ""))
    eth_hdr = dst_mac_bytes + src_mac_bytes + struct.pack("!H", 0x88CC)

    payload = b""

    # TLV 1: Chassis ID (Subtype 4 = MAC)
    chassis_val = b"\x04" + src_mac_bytes
    hdr1 = (1 << 9) | len(chassis_val)
    payload += struct.pack("!H", hdr1) + chassis_val

    # TLV 2: Port ID (Subtype 5 = Interface Name)
    port_val = b"\x05" + port_id.encode("utf-8")
    hdr2 = (2 << 9) | len(port_val)
    payload += struct.pack("!H", hdr2) + port_val

    # TLV 3: TTL (120s)
    ttl_val = struct.pack("!H", 120)
    hdr3 = (3 << 9) | 2
    payload += struct.pack("!H", hdr3) + ttl_val

    # TLV 4: Port Description
    pdesc_val = b"Conexao Estacao TI"
    hdr4 = (4 << 9) | len(pdesc_val)
    payload += struct.pack("!H", hdr4) + pdesc_val

    # TLV 5: System Name
    sname_val = sys_name.encode("utf-8")
    hdr5 = (5 << 9) | len(sname_val)
    payload += struct.pack("!H", hdr5) + sname_val

    # TLV 6: System Description
    sdesc_val = sys_descr.encode("utf-8")
    hdr6 = (6 << 9) | len(sdesc_val)
    payload += struct.pack("!H", hdr6) + sdesc_val

    # TLV 7: System Capabilities (Bridge + Router)
    caps_val = struct.pack("!HH", 0x0014, 0x0014)
    hdr7 = (7 << 9) | 4
    payload += struct.pack("!H", hdr7) + caps_val

    # TLV 8: Management Address (IPv4)
    import socket
    ip_bytes = socket.inet_aton(mgmt_ip)
    mgmt_val = bytes([len(ip_bytes) + 1, 1]) + ip_bytes + bytes([1, 0, 0, 0, 1, 0])
    hdr8 = (8 << 9) | len(mgmt_val)
    payload += struct.pack("!H", hdr8) + mgmt_val

    # TLV 127: IEEE 802.1 PVID (OUI 00:80:C2, Subtype 1)
    vlan_val = b"\x00\x80\xc2\x01" + struct.pack("!H", vlan_id)
    hdr127 = (127 << 9) | len(vlan_val)
    payload += struct.pack("!H", hdr127) + vlan_val

    # TLV 0: End of LLDPDU
    payload += struct.pack("!H", 0)

    return eth_hdr + payload


def run_tests():
    print("=" * 66)
    print("      TESTES: IDENTIFICADOR DE PORTA DE SWITCH (LLDP / CDP)       ")
    print("=" * 66)

    # ---------------------------------------------------------
    # TESTE 1: Parser de Regex de Números de Portas
    # ---------------------------------------------------------
    print("\n[TEST 1] Validação de Extração do Número Físico de Portas...")
    cases = [
        ("GigabitEthernet1/0/12", 12),
        ("FastEthernet0/24", 24),
        ("gi0/7", 7),
        ("ether3", 3),
        ("Port 16", 16),
        ("eth1/14", 14),
        ("ge-0/0/5", 5),
        ("Porta 2", 2),
        ("48", 48),
    ]
    for raw_str, expected in cases:
        got = extract_port_number(raw_str)
        assert got == expected, f"Falha para '{raw_str}': esperado {expected}, obteve {got}"
    print(f" -> {len(cases)} padrões de portas de diferentes fabricantes validados OK.")

    # ---------------------------------------------------------
    # TESTE 2: Estimativa de Quantidade Total de Portas
    # ---------------------------------------------------------
    print("\n[TEST 2] Validação de Estimativa de Quantidade Total de Portas...")
    assert estimate_total_ports("Cisco WS-C2960X-48TD-L", detected_port=12) == 48
    assert estimate_total_ports("Ubiquiti USW-24-PoE", detected_port=5) == 24
    assert estimate_total_ports("Aruba 2530-8G", detected_port=4) == 8
    assert estimate_total_ports("MikroTik CRS326", detected_port=30) == 48  # Auto-escala por porta detectada
    print(" -> Auto-detecção de total de portas (8, 16, 24, 48) OK.")

    # ---------------------------------------------------------
    # TESTE 3: Decodificação de Frame LLDP Bruto (IEEE 802.1AB) & Cisco CDP
    # ---------------------------------------------------------
    print("\n[TEST 3] Decodificação de Frame Bruto Ethernet LLDP & Cisco CDP...")
    synthetic_pkt = build_synthetic_lldp_frame(
        chassis_mac="00:1a:a1:4b:92:00",
        port_id="GigabitEthernet1/0/12",
        sys_name="SW-CORE-DISTRIB-01",
        sys_descr="Cisco Catalyst 2960X-24TD-L",
        mgmt_ip="192.168.1.254",
        vlan_id=10,
    )
    info = parse_lldp_frame(synthetic_pkt)
    assert info is not None, "Falha ao decodificar frame LLDP"
    assert info.port_id == "GigabitEthernet1/0/12", f"Port ID incorreto: {info.port_id}"
    assert info.port_number == 12, f"Port Number incorreto: {info.port_number}"
    assert info.switch_name == "SW-CORE-DISTRIB-01", f"Switch Name incorreto: {info.switch_name}"
    assert info.vlan_id == 10, f"VLAN ID incorreto: {info.vlan_id}"
    assert info.management_ip == "192.168.1.254", f"Management IP incorreto: {info.management_ip}"
    assert "Bridge" in str(info.capabilities), "Capacidade Bridge não identificada"
    assert info.total_ports == 24, f"Total de portas incorreto: {info.total_ports}"
    assert info.port_status_map.get(12) == "connected", "Porta 12 não marcada como conectada"
    print(f" -> Frame LLDP decodificado: {info.format_summary()} OK.")

    # Valida decodificação de frame Cisco CDP com cabeçalho LLC/SNAP
    eth_cdp = bytes.fromhex("01000cccccc0001122334455") + struct.pack("!H", 120)
    snap_cdp = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
    cdp_hdr = bytes([2, 180]) + b"\x00\x00"
    cdp_dev = b"SW-CISCO-CORE"
    cdp_t1 = struct.pack("!HH", 0x0001, 4 + len(cdp_dev)) + cdp_dev
    import socket
    cdp_ip = socket.inet_aton("192.168.1.1")
    cdp_addr = struct.pack("!IBB", 1, 1, 1) + b"\xcc" + struct.pack("!H", 4) + cdp_ip
    cdp_t2 = struct.pack("!HH", 0x0002, 4 + len(cdp_addr)) + cdp_addr
    cdp_port = b"GigabitEthernet1/0/1"
    cdp_t3 = struct.pack("!HH", 0x0003, 4 + len(cdp_port)) + cdp_port
    cdp_pkt = eth_cdp + snap_cdp + cdp_hdr + cdp_t1 + cdp_t2 + cdp_t3

    cdp_info = parse_cdp_packet(cdp_pkt)
    assert cdp_info is not None, "Falha ao decodificar frame Cisco CDP"
    assert cdp_info.switch_name == "SW-CISCO-CORE"
    assert cdp_info.management_ip == "192.168.1.1"
    assert cdp_info.port_number == 1
    assert cdp_info.protocol == "Cisco CDP"
    print(f" -> Frame Cisco CDP decodificado: {cdp_info.format_summary()} OK.")

    # ---------------------------------------------------------
    # TESTE 4: Detecção Inteligente e Validação de Capacidades do Sniffer L2
    # ---------------------------------------------------------
    print("\n[TEST 4] Validação de Candidatos e Permissões do Auxiliar L2...")
    candidates = get_l2_sniffer_candidates()
    assert len(candidates) > 0, "Nenhum candidato a binário auxiliar ipscan-l2-sniffer encontrado"
    best_bin = find_l2_sniffer_binary()
    assert best_bin is not None, "find_l2_sniffer_binary não retornou binário"
    has_cap = check_sniffer_binary_cap(best_bin)
    print(f" -> Melhor binário L2 selecionado: '{best_bin}' (CAP_NET_RAW: {has_cap}) OK.")

    # ---------------------------------------------------------
    # TESTE 5: Presets de Demonstração (Cisco, Ubiquiti, MikroTik, Aruba, Airoha)
    # ---------------------------------------------------------
    print("\n[TEST 5] Validação dos Presets de Demonstração...")
    p_cisco = get_demo_preset("cisco_24")
    assert p_cisco.total_ports == 24 and p_cisco.port_number == 12
    p_unifi = get_demo_preset("unifi_48")
    assert p_unifi.total_ports == 48 and p_unifi.port_number == 7
    p_mikrotik = get_demo_preset("mikrotik_24")
    assert p_mikrotik.total_ports == 24 and p_mikrotik.port_number == 3
    p_aruba = get_demo_preset("aruba_8")
    assert p_aruba.total_ports == 8 and p_aruba.port_number == 4
    p_airoha = get_demo_preset("airoha_24")
    assert p_airoha.total_ports == 24 and p_airoha.port_number == 16
    assert p_airoha.port_status_map.get(1) == "up", "Porta 1 (Uplink) deve estar up"
    assert p_airoha.port_status_map.get(16) == "connected", "Porta 16 deve estar connected"
    assert p_airoha.port_status_map.get(2) == "down", "Porta 2 deve estar down"
    print(" -> Todos os 5 presets de fabricantes (incluindo Airoha EN8851) validados OK.")

    # ---------------------------------------------------------
    # TESTE 6: Componente Gráfico SwitchFrontPanelWidget & Dialog
    # ---------------------------------------------------------
    print("\n[TEST 6] Renderização Gráfica do SwitchFrontPanelWidget e Diálogo...")
    app = QApplication.instance() or QApplication(sys.argv)

    widget = SwitchFrontPanelWidget(is_dark=True)
    widget.set_switch_data(
        total_ports=24,
        connected_port=12,
        connected_port_name="GigabitEthernet1/0/12",
        switch_brand="CISCO",
        switch_model="Catalyst 2960X-24TD-L",
    )
    widget.resize(900, 240)
    widget.show()
    from PyQt5.QtGui import QPixmap
    pix = QPixmap(900, 240)
    widget.render(pix)
    assert not pix.isNull(), "Falha ao renderizar SwitchFrontPanelWidget no pixmap"
    app.processEvents()

    # Valida clique em porta
    clicked_ports = []
    widget.port_clicked.connect(lambda p: clicked_ports.append(p))
    from PyQt5.QtCore import QPoint
    from PyQt5.QtGui import QMouseEvent
    rect_12 = widget._port_rects.get(12)
    assert rect_12 is not None, "Retângulo da porta 12 não foi mapeado"

    press_ev = QMouseEvent(
        QMouseEvent.MouseButtonPress,
        QPoint(int(rect_12.center().x()), int(rect_12.center().y())),
        Qt.LeftButton,
        Qt.LeftButton,
        Qt.NoModifier,
    )
    widget.mousePressEvent(press_ev)
    assert 12 in clicked_ports, f"Evento de clique não disparou para a porta 12 (recebeu {clicked_ports})"
    print(" -> Renderização visual e interação de clique na porta OK.")

    # Testa abertura do diálogo e diagnóstico de cabo TDR
    dialog = LLDPSwitchDialog(gateway_ip="192.168.1.254", is_dark=True)
    dialog.resize(1100, 750)
    dialog.show()
    app.processEvents()
    assert dialog.lbl_port_id.text() != "", "Card da porta está vazio"
    assert hasattr(dialog, "lbl_cable_len"), "Label de comprimento do cabo não encontrada"
    assert hasattr(dialog, "lbl_cable_status"), "Label de status do cabo não encontrada"
    assert hasattr(dialog, "btn_cable_diag"), "Botão de medição de cabo TDR não encontrado"
    dialog.close()
    print(" -> Diálogo LLDPSwitchDialog com medição de cabo TDR instanciado e validado OK.")

    print("\n" + "=" * 66)
    print("   TODOS OS TESTES DE LLDP E SWITCH CONCLUÍDOS COM 100% SUCESSO!  ")
    print("=" * 66)


if __name__ == "__main__":
    run_tests()
