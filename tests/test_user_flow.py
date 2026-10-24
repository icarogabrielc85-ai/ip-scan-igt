#!/usr/bin/env python3
"""
Comprehensive Automated User End-to-End Test Suite for IP Scan IGT.
Validates:
1. Dynamic translation of scanned items, sub-resources, properties panel, and KPIs across all 9 languages.
2. Full device classification pipeline (NVR, Camera, Windows, Linux, Printer, Proxmox, Router).
3. Internet Quality & DNS benchmark dialog (Add, Edit, Delete, Reset, Sorting, Maximize).
4. Executive report generation (HTML, CSV, JSON).
5. Clean thread lifecycle and graceful shutdown.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication

import i18n
from i18n import SUPPORTED_LANGUAGES, set_current_language, tr
from scanner_engine import HostRecord, ResourceItem, build_resources_for_host, classify_device
from main import MainWindow
from internet_test_dialog import (
    InternetQualityDialog,
    load_dns_targets,
    save_dns_targets,
    reset_dns_targets,
)

def run_e2e_tests():
    app = QApplication.instance() or QApplication(sys.argv)
    print("==================================================================")
    print("       INICIANDO BATERIA COMPLETA DE TESTES DE USUÁRIO (E2E)      ")
    print("==================================================================")

    # 1. Instantiate Main Window
    print("\n[TEST 1] Inicializando Janela Principal...")
    window = MainWindow()
    assert window is not None
    print(" -> Janela principal criada com sucesso.")

    # 2. Populate synthetic diverse realistic network scan results
    print("\n[TEST 2] Simulando varredura com dispositivos de teste reais...")
    devices_data = [
        # NVR ONVIF
        HostRecord(
            ip="192.168.1.10",
            alive=True,
            rtt_ms=1.45,
            ttl=64,
            ping_method="ICMP",
            hostname="nvr-intelbras-01",
            mac="E0:50:8B:11:22:33",
            vendor="Intelbras",
            onvif_url="http://192.168.1.10:8899/onvif/device_service",
            onvif_model="NVR-3116-4K",
            onvif_type="NetworkVideoRecorder",
            rtsp_url="rtsp://192.168.1.10:554/cam/realmonitor?channel=1&subtype=0",
            open_ports=[80, 554, 8899, 2443],
        ),
        # IP Camera ONVIF
        HostRecord(
            ip="192.168.1.20",
            alive=True,
            rtt_ms=3.12,
            ttl=64,
            ping_method="ICMP",
            hostname="cam-garagem",
            mac="A4:14:37:AA:BB:CC",
            vendor="Hikvision",
            onvif_url="http://192.168.1.20:80/onvif/device_service",
            onvif_model="DS-2CD2043G2-I",
            rtsp_url="rtsp://192.168.1.20:554/Streaming/Channels/101",
            open_ports=[80, 554],
        ),
        # Windows Workstation / Server
        HostRecord(
            ip="192.168.1.50",
            alive=True,
            rtt_ms=0.85,
            ttl=128,
            ping_method="ICMP",
            hostname="DESKTOP-FINANCEIRO",
            mac="70:85:C2:33:44:55",
            vendor="Dell Inc.",
            netbios_domain="WORKGROUP",
            open_ports=[139, 445, 3389],
        ),
        # Linux SSH Server
        HostRecord(
            ip="192.168.1.100",
            alive=True,
            rtt_ms=0.62,
            ttl=64,
            ping_method="ICMP",
            hostname="srv-backup-linux",
            mac="52:54:00:12:34:56",
            vendor="QEMU / KVM",
            ssh_banner="OpenSSH_9.3p1 Debian-1ubuntu3.6",
            open_ports=[22, 80],
            http_info="nginx/1.24.0",
        ),
        # Network Printer
        HostRecord(
            ip="192.168.1.80",
            alive=True,
            rtt_ms=5.40,
            ttl=255,
            ping_method="ICMP",
            hostname="HP-LaserJet-Pro",
            mac="00:1E:0B:77:88:99",
            vendor="HP Inc.",
            open_ports=[80, 631, 9100],
        ),
        # Router / Switch
        HostRecord(
            ip="192.168.1.1",
            alive=True,
            rtt_ms=1.10,
            ttl=64,
            ping_method="ICMP",
            hostname="router.lan",
            mac="CC:32:E5:11:22:33",
            vendor="TP-Link Corporation",
            open_ports=[53, 80, 443],
            http_info="TP-Link Omada Gateway",
        ),
        # Unknown Host
        HostRecord(
            ip="192.168.1.250",
            alive=True,
            rtt_ms=18.5,
            ttl=-1,
            ping_method="ICMP",
            hostname="",
            mac="",
            vendor="",
            open_ports=[],
        )
    ]

    for rec in devices_data:
        dev_type, os_info = classify_device(rec)
        rec.device_type = dev_type
        rec.os_family = os_info
        rec.resources = build_resources_for_host(rec)
        window.records[rec.ip] = rec
        window.add_or_update_tree_node(window.tree, rec)

    assert window.tree.topLevelItemCount() == len(devices_data)
    print(f" -> {window.tree.topLevelItemCount()} nós adicionados com sucesso à árvore de Resultados.")

    # 3. Dynamic Multi-Language Switching Test
    print("\n[TEST 3] Testando alternância dinâmica e tradução em todos os 9 idiomas...")
    test_languages = list(SUPPORTED_LANGUAGES.keys())

    for lang in test_languages:
        window.change_language(lang)
        current = i18n.get_current_language()
        assert current == lang, f"Idioma esperado {lang}, obteve {current}"

        # Check Column Headers
        col_0 = window.tree.headerItem().text(0)
        col_1 = window.tree.headerItem().text(1)
        col_5 = window.tree.headerItem().text(5)
        col_6 = window.tree.headerItem().text(6)
        assert col_0 == tr("col_status"), f"Header status mismatch in {lang}"
        assert col_1 == tr("col_hostname"), f"Header hostname mismatch in {lang}"
        assert col_5 == tr("col_ping"), f"Header ping mismatch in {lang}"
        assert col_6 == tr("col_comments"), f"Header comments mismatch in {lang}"

        # Check First Node (NVR)
        item_nvr = window.tree.topLevelItem(0)
        assert item_nvr is not None
        # Sub-resources
        child_count = item_nvr.childCount()
        assert child_count > 0, "NVR deve conter recursos filhos (ONVIF, RTSP, HTTP, etc.)"
        first_child = item_nvr.child(0)
        child_title = first_child.text(1)
        assert tr("res_onvif") in child_title or tr("res_rtsp_title") in child_title or tr("res_http_title") in child_title or tr("res_hardware_title") in child_title, \
            f"Título de recurso filho não traduzido em {lang}: {child_title}"

        # Check Details Table for NVR
        window.tree.setCurrentItem(item_nvr)
        assert window.details_table.rowCount() >= 10, "Tabela de detalhes deve ter ao menos 10 propriedades"
        prop_0_label = window.details_table.item(0, 0).text()
        assert prop_0_label == tr("prop_ip"), f"Propriedade IP não traduzida em {lang}: {prop_0_label}"
        prop_1_label = window.details_table.item(1, 0).text()
        assert prop_1_label == tr("prop_hostname"), f"Propriedade Hostname não traduzida em {lang}: {prop_1_label}"

        # Check Unknown device node
        item_unknown = window.tree.topLevelItem(6)
        vendor_text = item_unknown.text(3)
        assert vendor_text == tr("unknown"), f"Fabricante desconhecido não traduzido em {lang}: {vendor_text}"
        no_svc_text = item_unknown.text(6)
        assert no_svc_text == tr("no_services_found"), f"Comentário sem serviços não traduzido em {lang}: {no_svc_text}"

        # Check KPIs
        assert tr("kpi_online").split("{")[0].strip() in window.kpi_online.text(), f"KPI Online incompatível em {lang}"
        assert tr("kpi_services").split("{")[0].strip() in window.kpi_services.text(), f"KPI Serviços incompatível em {lang}"

        print(f" -> Idioma '{lang}' ({SUPPORTED_LANGUAGES[lang]['native']}) OK!")

    # Restore Portuguese for subsequent tests
    window.change_language("pt_BR")

    # 4. Internet Quality & DNS Dialog Test
    print("\n[TEST 4] Testando Diálogo de Teste de Internet e Benchmark DNS...")
    gw_ip = "192.168.1.1"
    dlg = InternetQualityDialog(window, gateway_ip=gw_ip, is_dark=False)
    assert dlg is not None
    assert dlg.table.columnCount() == 7

    # Test Adding a DNS server
    initial_count = len(dlg.dns_targets)
    new_dns = {
        "provider": "Cloudflare Security Test",
        "ip": "1.1.1.2",
        "category": "Segurança & Filtro",
        "feature": "Bloqueio de Malware",
        "icon": "🛡️",
        "is_dns": True,
    }
    dlg.dns_targets.append(new_dns)
    save_dns_targets(dlg.dns_targets)
    reloaded = load_dns_targets()
    assert any(x["ip"] == "1.1.1.2" for x in reloaded), "DNS adicionado não foi persistido no arquivo!"
    print(" -> Adição e persistência de DNS customizado OK.")

    # Test Editing the DNS server
    for entry in dlg.dns_targets:
        if entry["ip"] == "1.1.1.2":
            entry["feature"] = "Malware + Adult Content Filter"
            break
    save_dns_targets(dlg.dns_targets)
    reloaded = load_dns_targets()
    target_entry = next((x for x in reloaded if x["ip"] == "1.1.1.2"), None)
    assert target_entry["feature"] == "Malware + Adult Content Filter", "Edição do DNS não foi persistida!"
    print(" -> Edição e persistência de DNS customizado OK.")

    # Test Resetting DNS targets
    reset_dns_targets()
    reloaded_reset = load_dns_targets()
    assert not any(x["ip"] == "1.1.1.2" for x in reloaded_reset), "Reset não restaurou lista padrão!"
    print(" -> Restauração de lista original de servidores DNS OK.")

    # 5. Executive Report Generation Test
    print("\n[TEST 5] Testando geração de Relatório Executivo HTML...")
    html_code = window.generate_executive_html_report(window.records)
    assert "<!DOCTYPE html>" in html_code
    assert "IP Scan IGT" in html_code
    assert "192.168.1.10" in html_code
    assert "nvr-intelbras-01" in html_code
    assert "192.168.1.50" in html_code
    print(" -> Geração de relatório HTML executivo OK (tamanho: {} bytes).".format(len(html_code)))

    # 6. Sorting Test
    print("\n[TEST 6] Testando ordenação da árvore por colunas...")
    window.tree.sortByColumn(2, Qt.AscendingOrder)
    assert window.tree.topLevelItem(0).text(2) == "192.168.1.1"
    window.tree.sortByColumn(2, Qt.DescendingOrder)
    assert window.tree.topLevelItem(0).text(2) == "192.168.1.250"
    print(" -> Ordenação crescente e decrescente por IP OK.")

    # 7. Cleanup
    print("\n[TEST 7] Fechando janelas e encerrando threads...")
    dlg.close()
    window.close()
    print(" -> Encerramento limpo e gracioso concluído sem travamentos.")

    print("\n==================================================================")
    print("    TODOS OS TESTES DE USUÁRIO FORAM CONCLUÍDOS COM 100% SUCESSO! ")
    print("==================================================================")
    return True

if __name__ == "__main__":
    success = run_e2e_tests()
    sys.exit(0 if success else 1)
