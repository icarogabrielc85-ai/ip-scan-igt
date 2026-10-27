#!/usr/bin/env python3
"""
Test Suite for Subnet Auto-Detection and UI Synchronization in IP Scan IGT.
Validates:
1. Pure Python Netmask Validator (`_is_valid_ipv4_netmask`).
2. Linux live outbound routing socket (`_get_primary_outbound_ip`).
3. Linux ip route / ip addr show up detection.
4. Linux pure Python ioctl fallback (`_get_linux_ioctl_interfaces`).
5. Windows multilingual `ipconfig /all` parsing (CP850 / UTF-8 / CP1252) with IPv6/IPv4 multi-line default gateway.
6. Automatic prioritization: physical active interface with default gateway prioritized over virtual bridges.
7. MainWindow UI automatic initialization and real-time synchronization between Start IP, End IP, and Subnet Mask.
8. Support for typing CIDR notation (e.g. 192.168.10.0/24) into the Start IP field.
9. NetworkInterfaceDialog clean loading without parameter mismatch.
"""
import os
import sys
import unittest.mock as mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PyQt5.QtWidgets import QApplication

import scanner_engine
from scanner_engine import (
    get_all_network_interfaces,
    get_local_network_info,
    _get_linux_ioctl_interfaces,
    _get_primary_outbound_ip,
    _decode_console_output,
    get_default_gateways,
    _is_valid_ipv4_netmask,
)
from interface_dialog import NetworkInterfaceDialog
from main import MainWindow


def run_tests():
    app = QApplication.instance() or QApplication(sys.argv)
    print("==================================================================")
    print("    TESTE AUTOMATIZADO: AUTO-DETECÇÃO DE SUB-REDE E INTERFACE     ")
    print("==================================================================")

    # 1. Netmask Validator
    print("\n[TEST 1] Validador de Máscara de Sub-rede...")
    assert _is_valid_ipv4_netmask("255.255.255.0") is True
    assert _is_valid_ipv4_netmask("255.255.240.0") is True
    assert _is_valid_ipv4_netmask("255.0.0.0") is True
    assert _is_valid_ipv4_netmask("192.168.1.1") is False
    assert _is_valid_ipv4_netmask("") is False
    print(" -> Validação estrita de máscaras IPv4 OK.")

    # 2. Live Linux Detection
    print("\n[TEST 2] Detecção Ativa na Máquina Local...")
    live_info = get_local_network_info()
    assert live_info["ip"]
    assert live_info["start_ip"] and live_info["end_ip"]
    assert live_info["cidr"] and live_info["netmask"]
    print(f" -> Interface ativa: {live_info.get('name')} | IP: {live_info.get('ip')}/{live_info.get('cidr')} | Faixa: {live_info.get('start_ip')} - {live_info.get('end_ip')} OK.")

    # 3. Linux ioctl SIOCGIFADDR / SIOCGIFNETMASK fallback
    print("\n[TEST 3] Fallback via ioctl do Kernel Linux (Python Puro)...")
    gw_map = get_default_gateways()
    p_ip = _get_primary_outbound_ip()
    ioctl_ifaces = _get_linux_ioctl_interfaces(gw_map, p_ip, "test-host")
    assert len(ioctl_ifaces) >= 1
    assert ioctl_ifaces[0]["start_ip"] == live_info["start_ip"]
    print(f" -> Fallback ioctl ({ioctl_ifaces[0]['name']}: {ioctl_ifaces[0]['start_ip']} - {ioctl_ifaces[0]['end_ip']}) OK.")

    # 4. Windows CP850 Multilingual Simulation
    print("\n[TEST 4] Simulação Windows ipconfig /all CP850 (Português + Gateway IPv6/IPv4)...")
    sample_win_ipconfig_cp850 = (
        "Configuração de IP do Windows\r\n\r\n"
        "Adaptador Ethernet VirtualBox Host-Only Network:\r\n\r\n"
        "   Descrição . . . . . . . . . . . . . . . . . : VirtualBox Host-Only Ethernet Adapter\r\n"
        "   Endereço Físico . . . . . . . . . . . . . . : 0A-00-27-00-00-00\r\n"
        "   Endereço IPv4. . . . . . . .  . . . . . . . : 192.168.56.1(Preferencial)\r\n"
        "   Máscara de Sub-rede . . . . . . . . . . . . : 255.255.255.0\r\n"
        "   Gateway Padrão. . . . . . . . . . . . . . . : \r\n\r\n"
        "Adaptador Ethernet Ethernet:\r\n\r\n"
        "   Descrição . . . . . . . . . . . . . . . . . : Realtek PCIe GbE Family Controller\r\n"
        "   Endereço Físico . . . . . . . . . . . . . . : 00-23-09-02-CD-9F\r\n"
        "   Endereço IPv4. . . . . . . .  . . . . . . . : 192.168.111.46(Preferencial)\r\n"
        "   Máscara de Sub-rede . . . . . . . . . . . . : 255.255.255.0\r\n"
        "   Gateway Padrão. . . . . . . . . . . . . . . : fe80::1%12\r\n"
        "                                                 192.168.111.254\r\n"
    ).encode("cp850")

    with mock.patch.object(scanner_engine, "IS_WINDOWS", True), \
         mock.patch("subprocess.check_output", return_value=sample_win_ipconfig_cp850):
        win_ifaces = scanner_engine._get_windows_network_interfaces()
        assert len(win_ifaces) == 2, f"Esperado 2 interfaces, obteve {len(win_ifaces)}"
        # A placa física ativa com Gateway padrão deve estar em 1º lugar
        assert win_ifaces[0]["ip"] == "192.168.111.46"
        assert win_ifaces[0]["start_ip"] == "192.168.111.1"
        assert win_ifaces[0]["end_ip"] == "192.168.111.254"
        assert win_ifaces[0]["gateway"] == "192.168.111.254"
        assert win_ifaces[0]["is_default"] is True
        # A placa virtual VirtualBox deve estar em 2º lugar
        assert win_ifaces[1]["ip"] == "192.168.56.1"
        assert win_ifaces[1]["_is_virtual"] is True
    print(" -> Priorização de placa física e parsing CP850 no Windows OK.")

    # 5. UI Synchronization in MainWindow
    print("\n[TEST 5] Sincronização Dinâmica de Sub-rede na Janela Principal...")
    win = MainWindow()
    assert win.txt_start_ip.text() == live_info["start_ip"]
    assert win.txt_end_ip.text() == live_info["end_ip"]
    assert str(win.combo_mask.currentData()) == str(live_info["cidr"])

    # Modifica Start IP para outra sub-rede -> End IP deve atualizar automaticamente
    win.txt_start_ip.setText("10.20.30.1")
    assert win.txt_end_ip.text() == "10.20.30.254"

    # Digita notação CIDR diretamente (ex: 172.16.10.0/24)
    win.txt_start_ip.setText("172.16.10.0/24")
    assert win.txt_start_ip.text() == "172.16.10.1"
    assert win.txt_end_ip.text() == "172.16.10.254"
    assert win.combo_mask.currentData() == 24

    # Altera máscara para /23
    win.set_mask_cidr(23)
    win.on_mask_changed()
    assert win.txt_start_ip.text() == "172.16.10.1"
    assert win.txt_end_ip.text() == "172.16.11.254"

    # Alterna placa de rede via select_network_interface
    synthetic_iface = {
        "name": "wlan0",
        "interface": "wlan0",
        "ip": "192.168.2.55",
        "cidr": "24",
        "netmask": "255.255.255.0",
        "start_ip": "192.168.2.1",
        "end_ip": "192.168.2.254",
        "gateway": "192.168.2.1",
        "icon": "📶",
        "type": "Wi-Fi (Sem Fio)",
    }
    win.select_network_interface(synthetic_iface)
    assert win.txt_start_ip.text() == "192.168.2.1"
    assert win.txt_end_ip.text() == "192.168.2.254"
    print(" -> Sincronização de campos de IP, CIDR e troca de interfaces na UI OK.")

    # 6. NetworkInterfaceDialog modal test
    print("\n[TEST 6] Janela de Seleção de Interfaces de Rede...")
    dlg = NetworkInterfaceDialog(win, is_dark=False)
    assert dlg.table.rowCount() >= 1
    dlg.close()
    win.close()
    print(" -> Diálogo de placas de rede OK.")

    print("\n==================================================================")
    print("   TODOS OS TESTES DE SUB-REDE FORAM CONCLUÍDOS COM 100% SUCESSO! ")
    print("==================================================================")
    return True


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
