"""Npcap detection and install help (Windows only).

On Windows, LinkSight needs Npcap for packet capture. We detect it up front,
and when it's missing offer to download + launch the official installer
(rather than failing silently at sniff time).

Detection methods (in order):
  1. The "npcap" Windows service exists (sc query npcap)
  2. Npcap's install directory exists (C:\\Windows\\System32\\Npcap)

We do NOT auto-install silently: the official installer requires admin
consent, and silently elevating is bad behavior. We download the official
installer to a temp folder and launch it; the user walks the wizard once.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import webbrowser
from pathlib import Path

NPCAP_DOWNLOAD_PAGE = "https://npcap.com/#download"
# Versioned direct link — check npcap.com for current version periodically.
NPCAP_DIST_URL = "https://npcap.com/dist/npcap-1.88.exe"
NPCAP_INSTALL_DIRS = [
    r"C:\Windows\System32\Npcap",
    r"C:\Program Files\Npcap",
]


def npcap_installed() -> bool | None:
    """Return True if Npcap is present, False if not, None on non-Windows."""
    if sys.platform != "win32":
        return None
    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and "SERVICE_NAME: npcap" in result.stdout:
            return True
    except Exception:
        pass
    return any(Path(d).exists() for d in NPCAP_INSTALL_DIRS)


def download_installer(dest: Path | None = None) -> Path:
    """Download the official Npcap installer; returns the local file path."""
    import urllib.request

    dest = dest or Path(tempfile.gettempdir()) / "npcap-installer.exe"
    print(f"Downloading Npcap installer from {NPCAP_DIST_URL} ...")
    urllib.request.urlretrieve(NPCAP_DIST_URL, dest)
    print(f"Downloaded to {dest}")
    return dest


def launch_installer(installer_path: Path) -> None:
    """Launch the Npcap installer. On Windows this triggers the UAC prompt."""
    subprocess.Popen(
        [str(installer_path)],
        cwd=str(installer_path.parent),
    )


def open_download_page() -> None:
    webbrowser.open(NPCAP_DOWNLOAD_PAGE)
