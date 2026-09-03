"""Regenerate assets/splash_boot.png — the static image PyInstaller's onefile
bootloader shows while the bundle extracts (before Python even starts).

Run: python assets/make_splash_boot.py   (Qt offscreen is fine)
Mirrors linksight/ui/splash.py so the boot image and in-app splash feel like
one launch sequence.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QImage, QPainter, QPen

BG = QColor("#0f1117")
BORDER = QColor("#353848")
FG = QColor("#e0e0e0")
FG_FAINT = QColor("#808080")
ACCENT = QColor("#3b82f6")
MONO = "Consolas, 'SF Mono', Menlo, monospace"

W, H = 480, 220


def main() -> None:
    _app = QGuiApplication.instance() or QGuiApplication([])
    img = QImage(W, H, QImage.Format_ARGB32)
    img.fill(Qt.transparent)

    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing, True)

    # Panel with rounded corners
    p.setPen(QPen(BORDER, 1))
    p.setBrush(BG)
    p.drawRoundedRect(QRectF(0.5, 0.5, W - 1, H - 1), 10, 10)

    # Wordmark
    title = QFont("Segoe UI, Inter, Helvetica Neue, sans-serif", 26)
    title.setWeight(QFont.Bold)
    p.setFont(title)
    p.setPen(FG)
    p.drawText(26, 24, W - 52, 60, Qt.AlignLeft | Qt.AlignVCenter, "LinkSight")

    # Accent rule
    p.fillRect(26, 92, 64, 2, ACCENT)

    # Tagline
    sub = QFont("Segoe UI, Inter, Helvetica Neue, sans-serif", 11)
    p.setFont(sub)
    p.setPen(FG_FAINT)
    p.drawText(26, 106, W - 52, 30, Qt.AlignLeft | Qt.AlignVCenter,
               "LLDP/CDP Neighbor Discovery")

    # Muted boot line at bottom (mono)
    boot = QFont(MONO, 10)
    p.setFont(boot)
    p.setPen(QColor("#5a5f73"))
    p.drawText(26, H - 34, W - 52, 20, Qt.AlignLeft | Qt.AlignVCenter, "starting …")

    p.end()

    out = Path(__file__).resolve().parent / "splash_boot.png"
    ok = img.save(str(out))
    if not ok:
        print("failed to save", out)
        sys.exit(1)
    print(f"saved {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
