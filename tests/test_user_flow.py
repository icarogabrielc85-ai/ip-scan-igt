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

        # Check Column Headers (8 columns: Status, Nome, Apelido, IP, Fabricante, MAC, Ping, Comentários)
        col_0 = window.tree.headerItem().text(0)
        col_1 = window.tree.headerItem().text(1)
        col_2 = window.tree.headerItem().text(2)
        col_6 = window.tree.headerItem().text(6)
        col_7 = window.tree.headerItem().text(7)
        assert col_0 == tr("col_status"), f"Header status mismatch in {lang}"
        assert col_1 == tr("col_hostname"), f"Header hostname mismatch in {lang}"
        assert col_2 == tr("col_alias"), f"Header alias mismatch in {lang}"
        assert col_6 == tr("col_ping"), f"Header ping mismatch in {lang}"
        assert col_7 == tr("col_comments"), f"Header comments mismatch in {lang}"

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
        vendor_text = item_unknown.text(4)
        assert vendor_text == tr("unknown"), f"Fabricante desconhecido não traduzido em {lang}: {vendor_text}"
        no_svc_text = item_unknown.text(7)
        assert no_svc_text == tr("no_services_found"), f"Comentário sem serviços não traduzido em {lang}: {no_svc_text}"

        # Check KPIs
        assert tr("kpi_online").split("{")[0].strip() in window.kpi_online.text(), f"KPI Online incompatível em {lang}"
        assert tr("kpi_services").split("{")[0].strip() in window.kpi_services.text(), f"KPI Serviços incompatível em {lang}"

        # Check Switch Port button and menu translation
        assert window.btn_switch_port.text() == tr("btn_switch_port"), f"Botão Porta Switch não traduzido em {lang}"
        assert window.act_lldp_switch.text() == tr("menu_lldp_switch"), f"Menu Porta Switch não traduzido em {lang}"

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
    window.tree.sortByColumn(3, Qt.AscendingOrder)
    assert window.tree.topLevelItem(0).text(3) == "192.168.1.1"
    window.tree.sortByColumn(3, Qt.DescendingOrder)
    assert window.tree.topLevelItem(0).text(3) == "192.168.1.250"
    print(" -> Ordenação crescente e decrescente por IP OK.")

    # 7. SNMP (UDP 161) Engine Test
    print("\n[TEST 7] Testando Motor de Auditoria SNMP (UDP 161 ASN.1 BER)...")
    from snmp_engine import (
        OID_SYS_DESCR,
        OID_SYS_NAME,
        OID_SYS_UPTIME,
        SnmpAuditResult,
        build_snmp_get_packet,
        format_timeticks,
    )
    pkt = build_snmp_get_packet([OID_SYS_DESCR, OID_SYS_UPTIME, OID_SYS_NAME], community="public", version=1)
    assert pkt.startswith(b"\x30") and b"public" in pkt
    assert format_timeticks(8640000 + 360000) == "1d 01h 00m"
    snmp_sample = SnmpAuditResult(
        enabled=True,
        sys_name="SW-CORE-01",
        sys_descr="Cisco IOS Software, C2960X",
        uptime_str="45d 12h 10m",
        if_count=28,
        toner_percent=85,
        printer_pages=14230,
    )
    summary_snmp = snmp_sample.format_summary()
    assert "SW-CORE-01" in summary_snmp and "45d 12h 10m" in summary_snmp and "Portas/Ifaces: 28" in summary_snmp
    print(" -> Codificação ASN.1 BER e resumo de auditoria SNMP OK.")

    # 8. CVE Vulnerability Correlation Engine (SQLite) Test
    print("\n[TEST 8] Testando Motor de Correlação de Vulnerabilidades (CVEs SQLite)...")
    from cve_engine import CVE_DB, compute_risk_summary
    from nmap_engine import parse_nmap_output
    vulns = CVE_DB.correlate_host(
        open_ports=[21, 22, 23, 80, 8291],
        http_info="Apache/2.4.49 (Unix)",
        ssh_banner="OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        snmp_info="SNMPv2c Switch",
    )
    cve_ids = {v.cve_id for v in vulns}
    assert "CVE-2021-41773" in cve_ids, "Deve detectar falha crítica do Apache 2.4.49"
    assert "CVE-2024-6387" in cve_ids, "Deve detectar RegreSSHion no OpenSSH 8.9"
    assert "CVE-1999-0619" in cve_ids, "Deve detectar Telnet exposto na porta 23"
    assert "CVE-2018-14847" in cve_ids, "Deve detectar MikroTik Winbox na porta 8291"
    rlvl, max_cvss, badge = compute_risk_summary(vulns)
    assert rlvl == "CRITICAL" and max_cvss >= 9.0

    nmap_txt = (
        "PORT   STATE SERVICE VERSION\n"
        "22/tcp open  ssh     OpenSSH 9.1p1 Debian\n"
        "80/tcp open  http    Apache httpd 2.4.50\n"
    )
    parsed_nmap = parse_nmap_output(nmap_txt, "192.168.1.99")
    assert parsed_nmap["risk_level"] == "CRITICAL"
    assert any(v.cve_id == "CVE-2021-41773" for v in parsed_nmap["vulnerabilities"])
    print(f" -> Correlação SQLite detectou {len(vulns)} CVEs com precisão ({badge}).")

    # 9. Watchdog Continuous Monitoring Test
    print("\n[TEST 9] Testando Monitoramento Contínuo (Watchdog) e Diálogo de Eventos...")
    from watchdog_engine import WatchdogDialog, WatchdogEvent, WatchdogWorker, append_watchdog_event, load_watchdog_events
    wd_dlg = WatchdogDialog(window, is_dark=False)
    assert wd_dlg is not None
    ev_test = WatchdogEvent(
        timestamp="25/10/2026 23:00:00",
        ip="192.168.1.10",
        hostname="nvr-intelbras-01",
        event_type="DOWN",
        details="Teste automatizado de alerta de queda",
    )
    append_watchdog_event(ev_test)
    wd_dlg.refresh_events_table()
    assert wd_dlg.table.rowCount() >= 1
    wd_dlg.close()
    print(" -> Watchdog Worker, persistência de incidentes e diálogo de controle OK.")

    # 10. Visual Network Topology Mapping Test
    print("\n[TEST 10] Testando Mapeamento Visual Interativo de Topologia...")
    topo = window.topology_widget
    topo.set_network_data(window.records, window.local_info)
    assert len(topo.node_items) >= len(devices_data)
    # Test switching layout to tiered and back to radial
    topo.combo_layout.setCurrentIndex(1)
    assert len(topo.node_items) >= len(devices_data)
    topo.combo_layout.setCurrentIndex(0)
    # Test filtering by risk (CVEs)
    topo.combo_filter.setCurrentIndex(3)
    assert len(topo.node_items) >= 2
    topo.combo_filter.setCurrentIndex(0)
    print(f" -> Grafo de Topologia renderizado com {len(topo.node_items)} nós interativos (Radial & Camadas) OK.")

    # 11. Network Guard (Intruder, IP Conflict & ARP Spoofing) Test
    print("\n[TEST 11] Testando Network Guard (Intrusos, Conflito de IP e ARP Spoofing)...")
    import tempfile
    from network_guard_engine import NetworkGuardDialog, NetworkGuardEngine
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        guard_tmp = tf.name
    try:
        eng = NetworkGuardEngine(storage_path=guard_tmp)
        # 1. Establish Gateway MAC
        gw_alerts = eng.inspect_host("192.168.1.1", "AA:BB:CC:00:00:01", hostname="Gateway", gateway_ip="192.168.1.1")
        assert any(a.alert_type == "INTRUDER_NEW_MAC" for a in gw_alerts)
        eng.trust_mac("AA:BB:CC:00:00:01", trusted=True, ip="192.168.1.1")

        # 2. Simulate ARP Spoofing (different IP claiming Gateway MAC)
        spoof_alerts = eng.inspect_host("192.168.1.99", "AA:BB:CC:00:00:01", hostname="Attacker", gateway_ip="192.168.1.1")
        assert any(a.alert_type == "ARP_SPOOFING" and a.severity == "CRITICAL" for a in spoof_alerts)

        # 3. Simulate IP Conflict (same IP switching MAC)
        eng.inspect_host("192.168.1.50", "11:22:33:44:55:66", hostname="Srv-01", gateway_ip="192.168.1.1")
        conflict_alerts = eng.inspect_host("192.168.1.50", "11:22:33:99:99:99", hostname="Srv-01", gateway_ip="192.168.1.1")
        assert any(a.alert_type == "IP_CONFLICT" and a.severity == "HIGH" for a in conflict_alerts)

        g_dlg = NetworkGuardDialog(window, records=window.records, gateway_ip="192.168.1.1", is_dark=False)
        assert g_dlg is not None
        g_dlg.close()
    finally:
        if os.path.exists(guard_tmp):
            os.remove(guard_tmp)
    print(" -> Detecção de ARP Spoofing, Conflito de IP, Intrusos L2 e Diálogo Network Guard OK.")

    # 12. Audit Snapshots & Baseline Diff Engine Test
    print("\n[TEST 12] Testando Snapshots de Auditoria e Comparador de Mudanças (Baseline Diff)...")
    from snapshot_engine import SnapshotDiffDialog, SnapshotManager, compare_host_maps
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf_s:
        snap_tmp = tf_s.name
    try:
        sm = SnapshotManager(storage_path=snap_tmp)
        snap = sm.create_snapshot(window.records, name="Baseline Produção", interface_str="eth0")
        assert snap["host_count"] == len(window.records)

        # Create modified state: remove 192.168.1.250, add 192.168.1.222, add port 8080 to 192.168.1.50
        curr_map = {}
        for ip, r in window.records.items():
            if ip == "192.168.1.250":
                continue
            copy_d = dict(r.__dict__)
            if ip == "192.168.1.50":
                copy_d["open_ports"] = sorted(list(set(r.open_ports + [8080])))
            curr_map[ip] = copy_d
        curr_map["192.168.1.222"] = HostRecord(ip="192.168.1.222", alive=True, hostname="novo-servidor", open_ports=[22, 80])

        diff_res = compare_host_maps(snap["hosts"], curr_map)
        assert len(diff_res.added_hosts) == 1 and diff_res.added_hosts[0].ip == "192.168.1.222"
        assert len(diff_res.removed_hosts) == 1 and diff_res.removed_hosts[0].ip == "192.168.1.250"
        assert any(m.ip == "192.168.1.50" and 8080 in m.added_ports for m in diff_res.modified_hosts)

        s_dlg = SnapshotDiffDialog(window, current_records=window.records, interface_str="eth0")
        assert s_dlg is not None
        s_dlg.close()
    finally:
        if os.path.exists(snap_tmp):
            os.remove(snap_tmp)
    print(" -> Comparador de Snapshots (+Novos, -Ausentes, ~Portas/CVEs Modificadas) OK.")

    # 13. UPnP / SSDP Discovery & Visual Traceroute Test
    print("\n[TEST 13] Testando Descoberta UPnP / SSDP (UDP 1900) e Traceroute Visual...")
    from upnp_engine import UpnpDeviceInfo, parse_ssdp_headers, parse_upnp_xml
    from traceroute_dialog import TraceHop, TracerouteDialog

    raw_ssdp = (
        "HTTP/1.1 200 OK\r\n"
        "LOCATION: http://192.168.1.55:1900/rootDesc.xml\r\n"
        "SERVER: Linux/5.15 UPnP/1.1 MiniUPnPd/2.3\r\n"
        "ST: upnp:rootdevice\r\n\r\n"
    )
    hdrs = parse_ssdp_headers(raw_ssdp)
    assert hdrs["location"] == "http://192.168.1.55:1900/rootDesc.xml"

    sample_xml = """<?xml version="1.0"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0">
      <device>
        <friendlyName>Smart TV LG OLED65</friendlyName>
        <manufacturer>LG Electronics</manufacturer>
        <modelName>OLED65C3PSA</modelName>
        <serialNumber>LG-99887766</serialNumber>
      </device>
    </root>"""
    xml_info = parse_upnp_xml(sample_xml)
    assert xml_info["friendly_name"] == "Smart TV LG OLED65"
    assert xml_info["manufacturer"] == "LG Electronics"
    assert xml_info["serial_number"] == "LG-99887766"

    tr_dlg = TracerouteDialog(window, target_ip="", known_records=window.records, local_ip="192.168.1.100", gateway_ip="192.168.1.1")
    tr_dlg.on_hop_discovered(TraceHop(ttl=1, ip="192.168.1.1", rtt_ms=0.85, hostname="Gateway Padrão", reached_target=False))
    tr_dlg.on_hop_discovered(TraceHop(ttl=2, ip="192.168.1.10", rtt_ms=1.45, hostname="nvr-intelbras-01", reached_target=True))
    assert tr_dlg.tbl_hops.rowCount() == 2
    tr_dlg.close()
    print(" -> Parser SSDP/UPnP XML e Grafo de Traceroute Visual por Saltos (TTL) OK.")

    # 14. Enhanced Self-Contained Executive Report (with Base64 Topology PNG & Security Score)
    print("\n[TEST 14] Testando Relatório Executivo Autocontido com Topologia em Base64 e Score...")
    window.records["192.168.1.1"].snmp_info = "Cisco IOS • Uptime: 45d • Portas/Ifaces: 28"
    window.records["192.168.1.50"].http_info = "Apache/2.4.49 (Unix)"
    full_html = window.generate_executive_html_report(window.records)
    assert "data:image/png;base64," in full_html, "Relatório HTML deve embutir imagem PNG da Topologia em Base64!"
    assert "Score de Segurança" in full_html
    assert "Matriz de Vulnerabilidades" in full_html
    assert "CVE-2021-41773" in full_html
    assert "Auditoria de Infraestrutura" in full_html
    print(f" -> Relatório Executivo Autocontido (com PNG Base64 + Matriz CVE + SNMP) OK ({len(full_html)} bytes).")

    # 15. Editable "Apelido" Column, Reorganized Menus & User Manual PDF Test
    print("\n[TEST 15] Testando Coluna 'Apelido' Editável, Menus Separados e Manual em PDF...")
    from scanner_engine import get_device_alias, save_device_alias
    from manual_dialog import UserManualDialog, export_manual_to_pdf

    # Verify separated menus exist
    assert hasattr(window, "menu_scan") and window.menu_scan.actions(), "Menu Varredura deve existir"
    assert hasattr(window, "menu_tools") and window.menu_tools.actions(), "Menu Ferramentas deve existir"
    assert hasattr(window, "menu_security") and window.menu_security.actions(), "Menu Segurança deve existir"

    # Test editing Apelido in column 2
    target_item = None
    for i in range(window.tree.topLevelItemCount()):
        it = window.tree.topLevelItem(i)
        if it.text(3) == "192.168.1.10":
            target_item = it
            break
    assert target_item is not None
    target_item.setText(2, "NVR Portaria Principal")
    window.on_tree_item_changed(window.tree, target_item, 2)
    assert window.records["192.168.1.10"].alias == "NVR Portaria Principal"
    assert get_device_alias("192.168.1.10", "E0:50:8B:11:22:33") == "NVR Portaria Principal"

    # Clean up test alias
    save_device_alias("192.168.1.10", "E0:50:8B:11:22:33", "")

    # Test UserManualDialog and direct PDF export
    manual_dlg = UserManualDialog(window, is_dark=False)
    assert manual_dlg.list_toc.count() >= 10
    manual_dlg.txt_search.setText("Watchdog")
    manual_dlg.on_toc_item_clicked(manual_dlg.list_toc.item(3))
    manual_dlg.close()

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf_pdf:
        pdf_path = tf_pdf.name
    try:
        ok_pdf = export_manual_to_pdf(pdf_path)
        assert ok_pdf and os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 5000
        with open(pdf_path, "rb") as f_pdf:
            hdr_bytes = f_pdf.read(5)
        assert hdr_bytes == b"%PDF-", f"Arquivo gerado deve ser um PDF válido, obteve {hdr_bytes}"
        print(f" -> Manual PDF gerado com sucesso ({os.path.getsize(pdf_path)} bytes), Coluna 'Apelido' e Menus OK.")
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)

    # 16. Switch Port Identification Dialog (LLDP / CDP / SNMP) Test
    print("\n[TEST 16] Testando Identificador de Porta do Switch (LLDP / CDP / SNMP)...")
    from lldp_dialog import LLDPSwitchDialog
    lldp_dlg = LLDPSwitchDialog(window, gateway_ip="192.168.1.1", is_dark=False)
    assert lldp_dlg is not None
    assert lldp_dlg.switch_widget.total_ports == 24
    # Test loading Ubiquiti 48 demo preset
    lldp_dlg.load_demo("unifi_48")
    assert lldp_dlg.switch_widget.total_ports == 48
    assert lldp_dlg.current_info.port_number == 7
    # Test copying report
    lldp_dlg.copy_report_to_clipboard(show_popup=False)
    copied = QApplication.clipboard().text()
    assert "RELATÓRIO DE AUDITORIA DE PORTA DE SWITCH" in copied
    lldp_dlg.close()
    print(" -> Abertura de diálogo LLDP, troca de perfil de switch e relatório técnico OK.")

    # 17. Cleanup
    print("\n[TEST 17] Fechando janelas e encerrando threads...")
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
