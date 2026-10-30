#!/usr/bin/env python3
"""
Teste de Ciclo de Vida e Estabilidade de Threads do Diálogo Wi-Fi e Diagnóstico de Cabo.
Garante que fechamentos rápidos, cliques múltiplos e destruição de diálogos não geram SIGABRT
ou 'QThread: Destroyed while thread is still running'.
"""

import sys
import os
import unittest
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_diagnostic_engine import (
    deduce_wifi_standard,
    measure_gateway_wifi_ping,
    LocalWifiDiagWorker,
)
from cable_diagnostic_dialog import WifiDiagnosticDialog, CableDiagnosticDialog


app = QApplication.instance()
if not app:
    app = QApplication(sys.argv)


class TestWifiLifecycleAndStability(unittest.TestCase):
    def test_deduce_wifi_standard_no_false_wifi7(self):
        """Verifica se a presença da palavra 'beacon' em 'iw dev link' não classifica como Wi-Fi 7."""
        raw_iw_link = """
        Connected to 54:71:dd:ca:9e:b4 (on wlx54e6fc8d7cd4)
            SSID: NSA Almoxarifado
            freq: 2462.0
            RX: 32491425 bytes (109343 packets)
            TX: 142937 bytes (1866 packets)
            signal: -22 dBm
            rx bitrate: 1.0 MBit/s
            tx bitrate: 54.0 MBit/s MCS 3 40MHz
            bss flags: CTS-protection short-preamble short-slot-time
            dtim period: 1
            beacon int: 100
        """
        std = deduce_wifi_standard(2462, 54.0, "WPA2", raw_proto=raw_iw_link)
        self.assertNotIn("Wi-Fi 7", std)
        self.assertIn("Wi-Fi 4", std)

    def test_deduce_wifi_standard_real_wifi7(self):
        """Verifica se padrões reais de Wi-Fi 7 são classificados corretamente."""
        raw_wifi7 = "802.11be Extreme Throughput EHT-MCS 11 320MHz"
        std = deduce_wifi_standard(6100, 2400.0, "WPA3", raw_proto=raw_wifi7)
        self.assertIn("Wi-Fi 7", std)

    def test_deduce_wifi_standard_real_wifi6(self):
        """Verifica Wi-Fi 6."""
        raw_wifi6 = "802.11ax High Efficiency HE-MCS 11 80MHz"
        std = deduce_wifi_standard(5180, 1201.0, "WPA3", raw_proto=raw_wifi6)
        self.assertIn("Wi-Fi 6", std)

    def test_worker_stop_and_wait(self):
        """Testa parada cooperativa do LocalWifiDiagWorker."""
        worker = LocalWifiDiagWorker(interface_name="wlx54e6fc8d7cd4", force_demo=False)
        worker.start()
        # Para imediatamente
        worker.stop()
        finished = worker.wait(3000)
        self.assertTrue(finished)

    def test_dialog_close_mid_scan(self):
        """Testa fechamento imediato do WifiDiagnosticDialog durante a execução do worker sem crash."""
        dlg = WifiDiagnosticDialog(is_dark=True)
        # Worker deve estar executando ou prestes a executar
        dlg.run_wifi_measurement()
        # Fechamento imediato
        dlg.close()
        # Se chegou aqui sem SIGABRT, a limpeza de thread funcionou
        self.assertIsNone(dlg.wifi_worker)

    def test_dialog_multiple_clicks_protection(self):
        """Garante que cliques repetidos não sobrescrevem a thread ativa."""
        dlg = WifiDiagnosticDialog(is_dark=True)
        dlg.run_wifi_measurement()
        initial_worker = dlg.wifi_worker
        # Clique repetido imediato
        dlg.run_wifi_measurement()
        dlg.scan_nearby_wifi_action()
        # O worker deve ser o mesmo objeto, não re-instanciado
        self.assertIs(dlg.wifi_worker, initial_worker)
        dlg.close()


if __name__ == "__main__":
    unittest.main()
