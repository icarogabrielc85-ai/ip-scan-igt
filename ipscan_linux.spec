# -*- mode: python ; coding: utf-8 -*-

import os
import sys

block_cipher = None

added_files = [
    ('mac-vendors.txt', '.'),
    ('icon.png', '.'),
    ('icon.ico', '.'),
]

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        'PyQt5',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWidgets',
        'psutil',
        'ssh_dialog',
        'video_config_dialog',
        'system_doctor_dialog',
        'onvif_engine',
        'oui_db',
        'version',
        'ui_theme',
        'scanner_engine',
        'interface_dialog',
        'nmap_dialog',
        'nmap_engine',
        'ssl',
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

exe = EXE(
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
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.png',
)
