"""Generate NetProbe app icon (.ico + .icns source PNGs).

House style: engineered, dense, dark #13151f panel with #3b82f6 accent.
Motif: a center node with four connected neighbors — LLDP/CDP neighbor
discovery as a clean topology glyph.

Usage: python tools/make_icon.py
Output: netprobe_icon.png (1024), netprobe.ico (multi-size), netprobe.icns (mac)
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QImage, QPainter, QColor, QPen, QBrush, QPainterPath, QFont
from PySide6.QtWidgets import QApplication

ROOT = Path(__file__).resolve().parent.parent

BG = QColor("#13151f")
PANEL = QColor("#1a1d2e")
ACCENT = QColor("#3b82f6")
FG = QColor("#e5e7eb")
FG_DIM = QColor("#6b7280")
EDGE = QColor("#3b82f6")


def render(size: int) -> QImage:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    s = size / 1024.0  # scale factor from the 1024 design space

    def S(v: float) -> float:
        return v * s

    # rounded-square background
    bg = QPainterPath()
    r = S(80)
    bg.addRoundedRect(QRectF(0, 0, size, size), r, r)
    p.fillPath(bg, BG)

    # subtle inner panel ring (engineering detail)
    pen = QPen(QColor("#252836"), S(8))
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRoundedRect(QRectF(S(28), S(28), size - S(56), size - S(56)), S(48), S(48))

    # edges from center to the four neighbors
    c = QPointF(S(512), S(512))
    neighbors = [
        QPointF(S(512), S(272)),   # top
        QPointF(S(752), S(512)),   # right
        QPointF(S(512), S(752)),   # bottom
        QPointF(S(272), S(512)),   # left
    ]
    edge_pen = QPen(EDGE, S(26))
    edge_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(edge_pen)
    for n in neighbors:
        p.drawLine(c, n)

    # neighbor nodes
    for i, n in enumerate(neighbors):
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#3b82f6") if i == 0 else FG_DIM)
        p.drawEllipse(n, S(72), S(72))

    # center node (accent, prominent)
    p.setBrush(ACCENT)
    p.drawEllipse(c, S(112), S(112))
    p.setBrush(QColor("#0f1117"))
    p.drawEllipse(c, S(44), S(44))

    p.end()
    return img


def main() -> None:
    app = QApplication([])  # noqa: F841
    sizes = [16, 24, 32, 48, 64, 128, 256, 512, 1024]
    imgs = {sz: render(sz) for sz in sizes}

    png_path = ROOT / "netprobe_icon.png"
    imgs[1024].save(str(png_path))
    print("PNG:", png_path)

    # .ico — write multi-size via Pillow if available (Qt can't write ico)
    try:
        from PIL import Image
        ico = ROOT / "netprobe.ico"
        pil_imgs = []
        for sz in (16, 24, 32, 48, 64, 128, 256):
            qimg = imgs[sz]
            data = qimg.constBits().tobytes()
            pil = Image.frombuffer("RGBA", (sz, sz), data, "raw", "BGRA", 0, 1)
            pil_imgs.append(pil)
        pil_imgs[-1].save(str(ico), format="ICO", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
        print("ICO:", ico)
    except ImportError:
        print("Pillow not installed — skipping .ico (install: uv pip install pillow)")

    # .icns — build from PNGs via Pillow
    try:
        from PIL import Image
        icns = ROOT / "netprobe.icns"
        pil_1024 = Image.open(str(png_path)).convert("RGBA")
        # ICNS family: 512@2x (1024), 512, 256@2x (512), 256, 128@2x (256), 128
        icns_sizes = [(1024, 512, "ic10"), (512, 512, "ic09"), (512, 256, "ic08"),
                      (256, 256, "ic07"), (256, 128, "ic06"), (128, 128, "ic05")]
        entries = []
        for px, logical, key in icns_sizes:
            icon = pil_1024 if px == 1024 else pil_1024.resize((px, px), Image.LANCZOS)
            import io
            buf = io.BytesIO()
            icon.save(buf, format="PNG")
            entries.append((key, buf.getvalue()))
        with open(str(icns), "wb") as f:
            f.write(b"icns")
            import struct
            total = 8 + sum(8 + len(d) for _, d in entries)
            f.write(struct.pack(">I", total))
            for key, data in entries:
                f.write(key.encode("ascii"))
                f.write(struct.pack(">I", 8 + len(data)))
                f.write(data)
        print("ICNS:", icns)
    except ImportError:
        print("Pillow not installed — skipping .icns")


if __name__ == "__main__":
    main()
