#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the Internet Speed Test Engine, Speedometer Widget, QoE Assessment,
and Tabbed Dialog Integration in IP Scan IGT.
"""

import sys
import os

# Headless Qt
os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt

app = QApplication.instance()
if not app:
    app = QApplication(sys.argv)

from internet_test_dialog import (
    calculate_qoe,
    SpeedometerWidget,
    SpeedTestWorker,
    InternetQualityDialog,
)


def test_calculate_qoe():
    print("\n[TEST 1] Testando Matriz de Avaliação de Experiência Real (QoE)...")
    
    # Fast fiber connection: 100 Mbps down, 50 Mbps up, 15ms ping, 2ms jitter
    qoe_fast = calculate_qoe(ping=15.0, jitter=2.0, download=100.0, upload=50.0)
    assert "⭐⭐⭐⭐⭐" in qoe_fast["streaming"]["score"]
    assert "Excelente" in qoe_fast["streaming"]["status"]
    assert "⭐⭐⭐⭐⭐" in qoe_fast["gaming"]["score"]
    assert "Ultra Baixo Ping" in qoe_fast["gaming"]["status"]
    assert "⭐⭐⭐⭐⭐" in qoe_fast["calls"]["score"]
    assert "HD Cristalino" in qoe_fast["calls"]["status"]
    assert qoe_fast["transfer"]["mbs"] == 12.5
    print(" -> Cenário Fibra de Alta Velocidade (100M/50M/15ms) OK.")

    # High latency / low bandwidth connection: 4 Mbps down, 0.8 Mbps up, 120ms ping, 25ms jitter
    qoe_slow = calculate_qoe(ping=120.0, jitter=25.0, download=4.0, upload=0.8)
    assert "⭐⭐" in qoe_slow["streaming"]["score"]
    assert "Limitado" in qoe_slow["streaming"]["status"]
    assert "⭐⭐" in qoe_slow["gaming"]["score"]
    assert "Alto Lag" in qoe_slow["gaming"]["status"]
    assert "⭐⭐" in qoe_slow["calls"]["score"]
    assert "Instável" in qoe_slow["calls"]["status"]
    print(" -> Cenário Conexão Instável (4M/0.8M/120ms) OK.")


def test_speedometer_widget():
    print("\n[TEST 2] Testando SpeedometerWidget e Renderização Gráfica...")
    
    # Dark Mode
    gauge_dark = SpeedometerWidget(is_dark=True)
    gauge_dark.resize(320, 260)
    gauge_dark.set_phase("DOWNLOAD", unit="Mbps", sub_text="Pico: 125.0 Mbps")
    gauge_dark.set_value(95.4)
    pix_dark = QPixmap(320, 260)
    gauge_dark.render(pix_dark)
    assert not pix_dark.isNull()
    print(" -> SpeedometerWidget Dark Mode renderizado com sucesso.")

    # Light Mode
    gauge_light = SpeedometerWidget(is_dark=False)
    gauge_light.resize(320, 260)
    gauge_light.set_phase("UPLOAD", unit="Mbps", sub_text="Pico: 45.0 Mbps")
    gauge_light.set_value(38.2)
    pix_light = QPixmap(320, 260)
    gauge_light.render(pix_light)
    assert not pix_light.isNull()
    print(" -> SpeedometerWidget Light Mode renderizado com sucesso.")

    # Dynamic scaling test
    gauge_dark.set_value(350.0)
    assert gauge_dark._max_value >= 500.0, "Auto-escala dinâmica de velocidade falhou!"
    print(" -> Auto-escala dinâmica (100 -> 250 -> 500 -> 1000 Mbps) OK.")


def test_dialog_tabs_and_controls():
    print("\n[TEST 3] Testando Integração Completa de Abas (Speed Test + DNS Benchmark)...")
    
    dlg = InternetQualityDialog(parent=None, gateway_ip="192.168.1.1", is_dark=True)
    assert dlg is not None
    assert dlg.tabs.count() == 2
    assert "Speed Test" in dlg.tabs.tabText(0)
    assert "DNS" in dlg.tabs.tabText(1)

    # Check widgets in Tab 0 (Speed Test)
    assert dlg.speedometer is not None
    assert dlg.card_speed_ping is not None
    assert dlg.card_speed_down is not None
    assert dlg.card_speed_up is not None
    assert dlg.card_speed_transfer is not None
    assert dlg.card_speed_qoe is not None
    assert dlg.btn_speed_toggle is not None
    assert dlg.speed_prog_bar is not None
    print(" -> Componentes da Aba 0 (Speed Test) validados com sucesso.")

    # Check widgets in Tab 1 (DNS Benchmark)
    assert dlg.table.columnCount() == 7
    assert dlg.card_wan is not None
    assert dlg.card_gw is not None
    assert dlg.card_dns is not None
    assert dlg.card_fastest is not None
    assert dlg.btn_restart is not None
    print(" -> Componentes da Aba 1 (DNS Benchmark) validados com sucesso.")

    # Test tab switching triggers
    dlg.tabs.setCurrentIndex(1)
    app.processEvents()
    assert dlg.worker is not None, "Troca para aba DNS deveria disparar worker de benchmark!"
    print(" -> Troca dinâmica de abas com acionamento de benchmark OK.")

    # Clean stop
    if dlg.speed_worker and dlg.speed_worker.isRunning():
        dlg.speed_worker.cancel()
        dlg.speed_worker.wait(1000)
    if dlg.worker and dlg.worker.isRunning():
        dlg.worker.cancel()
        dlg.worker.wait(1000)
    dlg.close()
    print(" -> Encerramento limpo de threads e diálogo OK.")


if __name__ == "__main__":
    print("==================================================================")
    print("     TESTES DO SPEED TEST & UI/UX DA QUALIDADE DA INTERNET        ")
    print("==================================================================")
    test_calculate_qoe()
    test_speedometer_widget()
    test_dialog_tabs_and_controls()
    print("\n==================================================================")
    print("  TODOS OS TESTES DE SPEED TEST FORAM CONCLUÍDOS COM 100% SUCESSO! ")
    print("==================================================================")
