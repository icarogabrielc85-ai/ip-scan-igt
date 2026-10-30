# -*- mode: python ; coding: utf-8 -*-

import glob
import os
import sys

block_cipher = None

added_files = [
    ('mac-vendors.txt', '.'),
    ('icon.png', '.'),
    ('icon.ico', '.'),
]

# Coleta explícita das DLLs do Python e do Visual C++ Runtime / Universal CRT (evita erro "Failed to load Python DLL")
extra_binaries = []
if sys.platform.startswith('win'):
    search_dirs = [
        sys.base_prefix,
        sys.prefix,
        os.path.join(sys.base_prefix, 'DLLs'),
        os.path.join(sys.base_prefix, 'Library', 'bin'),
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32'),
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'downlevel'),
    ]
    dll_patterns = [
        'python3*.dll',
        'vcruntime140*.dll',
        'msvcp140*.dll',
        'concrt140*.dll',
        'vccorlib140*.dll',
        'ucrtbase*.dll',
        'api-ms-win-crt-*.dll',
    ]
    seen_dlls = set()
    for d in search_dirs:
        if not d or not os.path.isdir(d):
            continue
        for pat in dll_patterns:
            for dll_path in glob.glob(os.path.join(d, pat)):
                dll_name = os.path.basename(dll_path).lower()
                if dll_name not in seen_dlls and os.path.isfile(dll_path):
                    seen_dlls.add(dll_name)
                    extra_binaries.append((dll_path, '.'))

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=extra_binaries,
    datas=added_files,
    hiddenimports=[
        'PyQt5',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWidgets',
        'PyQt5.QtPrintSupport',
        'psutil',
        'ssh_dialog',
        'video_config_dialog',
        'system_doctor_dialog',
        'internet_test_dialog',
        'onvif_engine',
        'oui_db',
        'version',
        'i18n',
        'ui_theme',
        'scanner_engine',
        'interface_dialog',
        'nmap_dialog',
        'nmap_engine',
        'snmp_engine',
        'cve_engine',
        'watchdog_engine',
        'topology_widget',
        'network_guard_engine',
        'snapshot_engine',
        'upnp_engine',
        'traceroute_dialog',
        'lldp_dialog',
        'lldp_engine',
        'switch_visual_widget',
        'cable_diagnostic_dialog',
        'cable_diagnostic_engine',
        'wifi_diagnostic_dialog',
        'wifi_diagnostic_engine',
        'updater_engine',
        'manual_dialog',
        'sqlite3',
        'ctypes',
        'ssl',
        'certifi',
        'socket',
        'subprocess',
        'xml.etree.ElementTree',
        'urllib.request',
        'urllib.parse',
        'concurrent.futures',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'scipy', 'numpy', 'test', 'unittest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# 1) Executável Portátil Standalone (dist/IPScanIGT.exe) sem compressão UPX (upx=False evita corrupção da python311.dll)
exe_portable = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='IPScanIGT',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
)

# 2) Bundle de Diretório Nativo (dist/IPScanIGT_dir/) para o Instalador Inno Setup (zero extração em %TEMP%)
exe_dir = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='IPScanIGT',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    contents_directory='.',
    icon='icon.ico',
)

coll = COLLECT(
    exe_dir,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='IPScanIGT_dir',
)
