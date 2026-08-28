#!/usr/bin/env python3
"""LinkSight entry point.

Usage:
    python app.py               # live capture
    python app.py --demo        # replay a simulated network (no privileges needed)
"""

from __future__ import annotations

import argparse
import sys

from PySide6.QtWidgets import QApplication

from linksight.ui.theme import apply
from linksight.ui.controller import AppController
from linksight.ui.main_window import MainWindow


def _set_windows_app_id() -> None:
    """Give the window a stable AppUserModelID so the taskbar shows the app
    icon (otherwise Windows falls back to the generic icon for Qt apps)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "LinkSight.NeighborDiscovery.1"
        )
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="linksight", description="LLDP/CDP neighbor discovery")
    parser.add_argument("--demo", action="store_true", help="replay simulated frames (no capture privileges needed)")
    args = parser.parse_args(argv)

    _set_windows_app_id()
    app = QApplication(sys.argv[:1])
    app.setApplicationName("LinkSight")
    apply(app)

    controller = AppController()
    window = MainWindow(controller, demo=args.demo)
    window.show()

    # For offscreen screenshot mode: --shot FILE exits after rendering
    if "--shot" in sys.argv:
        idx = sys.argv.index("--shot")
        shot_path = sys.argv[idx + 1]
        window.grab().save(shot_path)
        print(f"screenshot saved: {shot_path}")
        controller.close()
        return 0

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

