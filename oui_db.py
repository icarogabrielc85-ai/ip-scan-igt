import json
import os
import re
import sys
import threading
import urllib.request
from i18n import tr
from config_paths import get_config_file

ONLINE_CACHE_FILE = get_config_file("oui_online_cache.json")


class OuiDatabase:
    def __init__(self):
        self.vendors = {}
        self.online_cache = {}
        self._loaded = False
        self._online_loaded = False
        self._lock = threading.Lock()

    def _ensure_online_cache_loaded(self):
        if self._online_loaded:
            return
        self._online_loaded = True
        try:
            if os.path.exists(ONLINE_CACHE_FILE):
                with open(ONLINE_CACHE_FILE, "r", encoding="utf-8") as f:
                    self.online_cache = json.load(f)
        except Exception:
            self.online_cache = {}

    def _save_online_cache(self):
        try:
            os.makedirs(os.path.dirname(ONLINE_CACHE_FILE), exist_ok=True)
            with open(ONLINE_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.online_cache, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def ensure_loaded(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            # Support PyInstaller frozen bundle and standard directory
            base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "mac-vendors.txt")
            if not os.path.exists(db_path):
                db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors.txt")

            if not os.path.exists(db_path):
                self._loaded = True
                return
            try:
                with open(db_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if len(line) > 6:
                            prefix = line[:6].upper()
                            vendor = line[6:].strip()
                            self.vendors[prefix] = vendor
            except Exception:
                pass
            self._loaded = True

    def lookup(self, mac: str) -> str:
        if not mac:
            return ""
        self.ensure_loaded()
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) >= 6:
            prefix = clean[:6]
            v = self.vendors.get(prefix, "")
            if v:
                return v

            # Check locally administered / randomized or virtual MAC prefixes
            first_byte = int(clean[:2], 16)
            if first_byte & 0x02:
                return tr("mac_local_private", "MAC Local / Virtual (Privado)")

            # Check persistent online cache
            self._ensure_online_cache_loaded()
            if prefix in self.online_cache:
                return self.online_cache[prefix]
        return ""

    def lookup_online(self, mac: str) -> str:
        """
        Consulta online leve para fabricantes desconhecidos com cache local permanente.
        """
        if not mac:
            return ""
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) < 6:
            return ""
        prefix = clean[:6]

        self._ensure_online_cache_loaded()
        if prefix in self.online_cache:
            return self.online_cache[prefix]

        try:
            from scanner_engine import robust_urlopen
            urlopen_fn = robust_urlopen
        except Exception:
            urlopen_fn = urllib.request.urlopen

        try:
            url = f"https://api.maclookup.app/v2/macs/{prefix}/company/name"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "IPScanIGT/2.6.2"}
            )
            with urlopen_fn(req, timeout=1.5) as resp:
                if resp.status == 200:
                    data = resp.read().decode("utf-8").strip()
                    if data and not data.startswith("{") and len(data) < 60:
                        self.online_cache[prefix] = data
                        self._save_online_cache()
                        return data
        except Exception:
            pass

        return ""

OUI_DB = OuiDatabase()
