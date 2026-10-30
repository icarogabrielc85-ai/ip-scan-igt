#!/usr/bin/env python3
"""
Testes Automatizados para o Motor e Diálogo de Diagnóstico de Cabo de Rede e Wi-Fi.
"""
import os
import sys

# Garante raiz do projeto no path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtWidgets import QApplication

from cable_diagnostic_dialog import CableDiagnosticDialog
from cable_diagnostic_engine import (
    CableDiagResult,
    diagnose_nic_cable,
    get_nic_hardware_info,
)
from wifi_diagnostic_engine import (
    WifiDiagResult,
    diagnose_wifi,
    get_demo_wifi_result,
    get_wifi_interfaces,
)


def run_tests():
    print("=" * 68)
    print("      TESTES: DIAGNÓSTICO E MEDIÇÃO DE CABO E WI-FI (NIC / WLAN)    ")
    print("=" * 68)

    # 1. Teste de Hardware da Placa Ethernet
    print("\n[TEST 1] Extração de Hardware e Driver da Placa de Rede...")
    hw = get_nic_hardware_info("enp7s0")
    assert isinstance(hw, dict)
    assert "model" in hw and "driver" in hw
    print(f" -> Modelo: {hw['model']} | Driver: {hw['driver']} OK.")

    # 2. Teste de Diagnóstico Físico do Cabo
    print("\n[TEST 2] Diagnóstico Físico do Cabo na Interface Local (enp7s0)...")
    res = diagnose_nic_cable("enp7s0", "192.168.111.254")
    assert isinstance(res, CableDiagResult)
    assert res.interface_name == "enp7s0"
    assert res.link_up is True, "Link físico da placa enp7s0 deve estar UP"
    assert res.speed_mbps == 1000, f"Velocidade esperada 1000 Mbps, obteve {res.speed_mbps}"
    assert res.cable_length_m > 0.0, f"Comprimento deve ser > 0, obteve {res.cable_length_m}"
    assert "4 Pares" in res.pairs_status, f"Pares esperados 4, obteve {res.pairs_status}"
    print(f" -> Diagnóstico: {res.format_summary()} OK.")

    # 3. Teste com Interface Inexistente / Desconectada
    print("\n[TEST 3] Diagnóstico em Interface Inexistente (Circuito Aberto)...")
    res_fake = diagnose_nic_cable("eth_fake99")
    assert res_fake.link_up is False
    assert "Desconectado" in res_fake.pairs_status
    print(" -> Detecção correta de interface desconectada OK.")

    # 4. Teste do Motor de Diagnóstico Wi-Fi
    print("\n[TEST 4] Teste do Motor de Diagnóstico Wi-Fi...")
    wifi_ifaces = get_wifi_interfaces()
    print(f" -> Interfaces Wi-Fi detectadas no host: {wifi_ifaces}")
    wifi_res = diagnose_wifi()
    assert isinstance(wifi_res, WifiDiagResult)

    demo_res = get_demo_wifi_result()
    assert demo_res.has_hardware is True
    assert demo_res.is_connected is True
    assert demo_res.ssid == "IGT-Enterprise-Wi-Fi6"
    assert demo_res.signal_percent == 94
    assert demo_res.signal_dbm == -48
    assert "Wi-Fi 6" in demo_res.wifi_standard
    assert len(demo_res.nearby_networks) >= 3
    print(f" -> Wi-Fi Demo: {demo_res.ssid} • {demo_res.signal_percent}% • {demo_res.wifi_standard} OK.")

    # 5. Teste de Interface Gráfica CableDiagnosticDialog (Ambas as Abas)
    print("\n[TEST 5] Renderização Gráfica do CableDiagnosticDialog (Cabo & Wi-Fi)...")
    app = QApplication.instance() or QApplication(sys.argv)
    dlg = CableDiagnosticDialog(initial_iface="enp7s0", is_dark=True, initial_tab="cable")
    dlg.resize(980, 720)
    dlg.show()
    app.processEvents()

    # Valida aba de cabo
    assert dlg.stack.currentIndex() == 0
    assert dlg.lbl_big_length.text() != ""
    assert dlg.combo_iface.count() > 0

    # Alterna para aba de Wi-Fi
    dlg.switch_to_wifi()
    app.processEvents()
    assert dlg.stack.currentIndex() == 1

    # Carrega dados do demo para validar renderização de Wi-Fi
    dlg._on_wifi_diag_success(demo_res)
    app.processEvents()
    assert "-48 dBm" in dlg.lbl_big_signal.text()
    assert "IGT-Enterprise-Wi-Fi6" in dlg.lbl_wifi_ssid_bssid.text()
    assert dlg.table_nearby.rowCount() == len(demo_res.nearby_networks)

    # Alterna de volta para Cabo
    dlg.switch_to_cable()
    app.processEvents()
    assert dlg.stack.currentIndex() == 0

    dlg.close()
    print(" -> Navegação entre abas Cabo e Wi-Fi e renderização validadas OK.")

    print("\n" + "=" * 68)
    print("   TODOS OS TESTES DE CABO E WI-FI CONCLUÍDOS COM 100% SUCESSO!   ")
    print("=" * 68)


if __name__ == "__main__":
    run_tests()
