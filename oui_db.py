import os
import re
import sys
import threading

class OuiDatabase:
    def __init__(self):
        self.vendors = {}
        self._loaded = False
        self._lock = threading.Lock()

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
            v = self.vendors.get(clean[:6], "")
            if v:
                return v
            # Check locally administered / randomized or virtual MAC prefixes
            first_byte = int(clean[:2], 16)
            if first_byte & 0x02:
                return "MAC Local / Virtual (Privado)"
        return ""

OUI_DB = OuiDatabase()
