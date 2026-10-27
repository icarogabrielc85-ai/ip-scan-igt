#!/usr/bin/env python3
"""
Config Paths Utility for IP Scan IGT.
Provides standard, cross-platform configuration and data storage paths:
- Windows: %APPDATA%\\IPScanIGT (e.g. C:\\Users\\<User>\\AppData\\Roaming\\IPScanIGT)
- Linux: ~/.config/ipscan-igt (with seamless backwards-compatible fallback to ~/.config/linux-ipscan)
"""
import os
import shutil
import sys

IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"


def get_config_dir() -> str:
    """
    Retorna o diretório de dados/configuração adequado para o sistema operacional:
    - No Windows: %APPDATA%\\IPScanIGT
    - No Linux / Unix: ~/.config/linux-ipscan (ou ~/.config/ipscan-igt)
    Garante a criação do diretório e a migração de configurações legadas.
    """
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA")
        if appdata:
            base_dir = os.path.join(appdata, "IPScanIGT")
        else:
            base_dir = os.path.expanduser("~/AppData/Roaming/IPScanIGT")
    else:
        # No Linux, prioriza ~/.config/linux-ipscan se já existir por retrocompatibilidade
        legacy_dir = os.path.expanduser("~/.config/linux-ipscan")
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if os.path.exists(legacy_dir):
            base_dir = legacy_dir
        elif xdg_config:
            base_dir = os.path.join(xdg_config, "ipscan-igt")
        else:
            base_dir = os.path.expanduser("~/.config/ipscan-igt")

    try:
        os.makedirs(base_dir, exist_ok=True)
    except Exception:
        pass

    # Migração automática no Windows caso existam arquivos salvos no formato antigo ~/.config/
    if IS_WINDOWS:
        for legacy_candidate in [
            os.path.expanduser("~/.config/linux-ipscan"),
            os.path.expanduser("~/.config/ipscan-igt"),
        ]:
            if os.path.exists(legacy_candidate) and os.path.abspath(legacy_candidate) != os.path.abspath(base_dir):
                try:
                    for item in os.listdir(legacy_candidate):
                        src = os.path.join(legacy_candidate, item)
                        dst = os.path.join(base_dir, item)
                        if not os.path.exists(dst) and os.path.isfile(src):
                            shutil.copy2(src, dst)
                except Exception:
                    pass

    return base_dir


def get_config_file(filename: str) -> str:
    """
    Retorna o caminho absoluto de um arquivo de configuração dentro do diretório oficial.
    Se o arquivo não existir no diretório oficial mas existir em local legado, copia automaticamente.
    """
    target_dir = get_config_dir()
    target_path = os.path.join(target_dir, filename)

    if not os.path.exists(target_path):
        for alt_dir in [
            os.path.expanduser("~/.config/ipscan-igt"),
            os.path.expanduser("~/.config/linux-ipscan"),
        ]:
            alt_path = os.path.join(alt_dir, filename)
            if os.path.exists(alt_path) and os.path.isfile(alt_path):
                try:
                    shutil.copy2(alt_path, target_path)
                    break
                except Exception:
                    return alt_path

    return target_path
