"""MAC vendor lookup via IEEE OUI database (same design as wifi-explorer).

On first use, downloads the IEEE OUI list and caches it in a small SQLite DB.
Falls back gracefully (offline, first-run failure) to returning "".
"""

from __future__ import annotations

import os
import re
import sqlite3
import urllib.request
from pathlib import Path

_CACHE_DIR = Path(os.path.expanduser("~")) / ".netprobe"
_CACHE_DB = _CACHE_DIR / "oui.db"
_IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

_OUI_CACHE: dict[str, str] = {}
_db: sqlite3.Connection | None = None
_download_attempted = False


def _ensure_db() -> sqlite3.Connection | None:
    global _db
    if _db is not None:
        return _db
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _db = sqlite3.connect(str(_CACHE_DB))
        _db.execute("CREATE TABLE IF NOT EXISTS oui (oui TEXT PRIMARY KEY, vendor TEXT)")
        _db.commit()
        return _db
    except Exception:
        return None


def _download_oui_database() -> bool:
    global _download_attempted
    _download_attempted = True
    try:
        req = urllib.request.Request(_IEEE_OUI_URL, headers={"User-Agent": "NetProbe/0.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return False

    db = _ensure_db()
    if db is None:
        return False
    pattern = re.compile(
        r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$"
    )
    count = 0
    try:
        db.execute("BEGIN TRANSACTION")
        db.execute("DELETE FROM oui")
        for line in data.splitlines():
            m = pattern.match(line)
            if m:
                oui = f"{m.group(1)}{m.group(2)}{m.group(3)}".upper()
                vendor = m.group(4).strip()
                if len(vendor) > 120:
                    vendor = vendor[:117] + "..."
                db.execute("INSERT OR REPLACE INTO oui (oui, vendor) VALUES (?, ?)", (oui, vendor))
                count += 1
        db.execute("COMMIT")
    except Exception:
        try:
            db.execute("ROLLBACK")
        except Exception:
            pass
        return False
    return count > 0


def _init_cache() -> None:
    global _OUI_CACHE
    if _OUI_CACHE or _download_attempted:
        return
    db = _ensure_db()
    if db is None:
        return
    try:
        row = db.execute("SELECT COUNT(*) FROM oui").fetchone()
        if row and row[0] > 0:
            rows = db.execute("SELECT oui, vendor FROM oui LIMIT 500").fetchall()
            _OUI_CACHE = {r[0]: r[1] for r in rows}
        elif not _download_attempted:
            _download_oui_database()
            _init_cache()
    except Exception:
        pass


def lookup_vendor(mac: str) -> str:
    """Look up vendor name for a MAC (XX:XX:XX:XX:XX:XX). Empty string if unknown."""
    if not mac or len(mac) < 8:
        return ""
    oui = mac.replace(":", "").replace("-", "").replace(".", "").upper()[:6]

    if oui in _OUI_CACHE:
        return _OUI_CACHE[oui]

    _init_cache()
    if oui in _OUI_CACHE:
        return _OUI_CACHE[oui]

    db = _ensure_db()
    if db is not None:
        try:
            row = db.execute("SELECT vendor FROM oui WHERE oui = ?", (oui,)).fetchone()
            if row:
                _OUI_CACHE[oui] = row[0]
                return row[0]
        except Exception:
            pass
    return ""
