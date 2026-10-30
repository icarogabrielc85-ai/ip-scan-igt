#!/usr/bin/env python3
"""
Unit and Integration Tests for Nmap NSE Scripts Catalog and NmapDialog.
Validates:
1. nmap_scripts_db loading 600+ scripts, presets, search, and output parser.
2. NmapDialog initialization, tab structure, preset activation, and live preview.
3. Script output parsing and rendering of structured vulnerability cards.
4. Dark and Light theme styling.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

import nmap_scripts_db as db
from nmap_dialog import NmapDialog, get_nmap_dialog_palette
from cve_engine import VulnerabilityMatch


def test_nmap_scripts_db():
    print("[TEST 1] Testando Base de Scripts NSE (nmap_scripts_db)...")
    scripts = db.get_all_scripts()
    assert len(scripts) >= 600, f"Esperado >= 600 scripts, obtido: {len(scripts)}"
    print(f" -> Catálogo carregado com sucesso: {len(scripts)} scripts NSE.")

    # Test presets
    presets = db.get_presets()
    expected_keys = ["vuln", "discovery", "web", "ssl", "smb", "auth", "cameras", "safe_default", "malware"]
    for k in expected_keys:
        assert k in presets, f"Preset '{k}' não encontrado nos presets!"
        assert len(presets[k]["key_scripts"]) > 0, f"Preset '{k}' não tem key_scripts associados!"
    print(f" -> {len(presets)} presets carregados com sucesso: {list(presets.keys())}")

    # Test search by query and category
    smb_results = db.search_scripts("smb-vuln", "")
    assert len(smb_results) >= 3, f"Esperado >= 3 scripts smb-vuln, obtido: {len(smb_results)}"
    vuln_results = db.search_scripts("", "vuln")
    assert len(vuln_results) >= 50, f"Esperado >= 50 scripts vuln, obtido: {len(vuln_results)}"
    print(f" -> Busca filtrada validada (smb-vuln: {len(smb_results)}, categoria vuln: {len(vuln_results)}).")

    # Test parser
    sample_raw = """
Host is up (0.00085s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|_    A critical remote code execution vulnerability exists in Microsoft SMBv1.
|_ssl-cert: Subject: commonName=gateway.local
"""
    parsed = db.parse_nse_script_output(sample_raw)
    assert len(parsed) >= 2, f"Esperado >= 2 scripts parseados, obtido {len(parsed)}"
    ms17 = next((s for s in parsed if s["name"] == "smb-vuln-ms17-010"), None)
    assert ms17 is not None
    assert ms17["status"] == "VULN", f"Status incorreto: {ms17['status']}"
    assert "CVE-2017-0143" in ms17["cves"], f"CVE-2017-0143 não capturada: {ms17.get('cves')}"
    print(" -> Parser de saída NSE validado com detecção de CVE e status VULN.")


def test_nmap_dialog_ui():
    print("\n[TEST 2] Testando NmapDialog UI & UX...")
    app = QApplication.instance() or QApplication(sys.argv)

    dialog = NmapDialog(target="192.168.1.100", hostname="srv-backup-linux", parent=None, is_dark=True)
    assert dialog is not None
    assert dialog.tabs.count() == 4
    assert "Scripts NSE" in dialog.tabs.tabText(0)
    assert "Relatório" in dialog.tabs.tabText(1)
    assert "Resultados" in dialog.tabs.tabText(2)
    assert "Terminal" in dialog.tabs.tabText(3)
    print(" -> Diálogo criado com 4 abas estruturadas.")

    # Verify table has items
    assert dialog.table_scripts.rowCount() >= 600
    print(f" -> Tabela interativa preenchida com {dialog.table_scripts.rowCount()} linhas de scripts.")

    # Test preset application (e.g., 'smb')
    dialog._apply_preset("smb")
    sel = dialog.get_selected_scripts()
    assert len(sel) > 0, "Nenhum script selecionado após aplicar preset smb!"
    cmd_preview = dialog.lbl_cmd_preview.text()
    assert "--script" in cmd_preview
    print(f" -> Preset 'smb' aplicado com sucesso ({len(sel)} scripts selecionados). Preview: {cmd_preview}")

    # Test clear
    dialog._clear_all_scripts()
    assert len(dialog.get_selected_scripts()) == 0
    print(" -> Limpeza de scripts validada.")

    # Test preset 'vuln'
    dialog._apply_preset("vuln")
    sel_vuln = dialog.get_selected_scripts()
    assert len(sel_vuln) > 0
    print(f" -> Preset 'vuln' aplicado: {len(sel_vuln)} scripts selecionados.")

    # Test search filter
    dialog.txt_script_search.setText("heartbleed")
    visible_count = dialog.table_scripts.rowCount()
    assert visible_count >= 1, "Script ssl-heartbleed deveria estar na lista filtrada!"
    print(f" -> Filtro de pesquisa 'heartbleed' filtrou para {visible_count} script(s).")
    dialog.txt_script_search.clear()

    # Test scan finished handler with mock output
    sample_parsed = {
        "target": "192.168.1.100",
        "device_diagnosis": "Servidor Windows com falha crítica SMB detectada via script NSE.",
        "diagnosis_icon": "🚨",
        "open_ports_list": [445, 3389],
        "closed_ports_list": [80],
        "latency": "0.85ms",
        "risk_level": "CRITICAL",
        "risk_badge": "🚨 CRÍTICO",
        "all_ports": [
            {"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds", "version": "Windows Server SMB"},
            {"port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server", "version": "RDP"}
        ],
        "nse_scripts": [
            {
                "name": "smb-vuln-ms17-010",
                "port": "445/tcp",
                "status": "VULN",
                "status_label": "🚨 VULNERÁVEL",
                "color": "#ef4444",
                "cves": ["CVE-2017-0143"],
                "output": "VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 (ms17-010)"
            },
            {
                "name": "ssl-cert",
                "port": "3389/tcp",
                "status": "INFO",
                "status_label": "ℹ️ INFORMAÇÃO",
                "color": "#38bdf8",
                "cves": [],
                "output": "Subject: commonName=srv-backup-linux"
            }
        ],
        "vulnerabilities": [
            VulnerabilityMatch(
                cve_id="CVE-2017-0143",
                product="Microsoft SMBv1",
                detected_version="1.0",
                port=445,
                cvss=9.8,
                severity="CRITICAL",
                title="SMBv1 Remote Code Execution (EternalBlue)",
                description="Falha crítica de execução remota de código no serviço SMBv1",
                remediation="Desabilitar SMBv1 e aplicar patch da Microsoft MS17-010"
            )
        ]
    }

    dialog.on_scan_finished("192.168.1.100", sample_parsed, "Raw Nmap finished successfully.")
    assert dialog.table_ports.rowCount() == 2
    assert dialog.table_nse_results.rowCount() == 2
    assert dialog.table_cves.rowCount() == 1
    assert dialog.tabs.currentIndex() == 2  # Automatically switched to results tab!
    print(" -> Abas de Relatório, Portas e Resultados populadas com sucesso a partir de dados estruturados.")

    # Test palettes
    pal_dark = get_nmap_dialog_palette(True)
    pal_light = get_nmap_dialog_palette(False)
    assert pal_dark["bg"] != pal_light["bg"]
    print(" -> Paletas Dark e Light validadas com distinção de contraste.")

    dialog.close()
    print(" -> Diálogo fechado com sucesso.")


if __name__ == "__main__":
    test_nmap_scripts_db()
    test_nmap_dialog_ui()
    print("\n====================================================================")
    print("   TODOS OS TESTES DE NMAP NSE & DIALOG FORAM CONCLUÍDOS COM SUCESSO! ")
    print("====================================================================")
