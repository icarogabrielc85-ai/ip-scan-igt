#!/usr/bin/env python3
"""
Testes Automatizados para o Motor e Diálogo de Diagnóstico de Cabo de Rede via Placa Local.
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


def run_tests():
    print("=" * 66)
    print("      TESTES: DIAGNÓSTICO E MEDIÇÃO DE CABO VIA PLACA LOCAL       ")
    print("=" * 66)

    # 1. Teste de Hardware da Placa
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

    # 4. Teste de Interface Gráfica CableDiagnosticDialog
    print("\n[TEST 4] Renderização Gráfica do CableDiagnosticDialog...")
    app = QApplication.instance() or QApplication(sys.argv)
    dlg = CableDiagnosticDialog(initial_iface="enp7s0", is_dark=True)
    dlg.resize(920, 680)
    dlg.show()
    app.processEvents()
    assert dlg.lbl_big_length.text() != ""
    assert dlg.combo_iface.count() > 0
    dlg.close()
    print(" -> Diálogo gráfico instanciado e validado OK.")

    print("\n" + "=" * 66)
    print("   TODOS OS TESTES DE CABO LOCAL CONCLUÍDOS COM 100% SUCESSO!   ")
    print("=" * 66)


if __name__ == "__main__":
    run_tests()
