#!/usr/bin/env python3
"""LinkSight entry point.

Usage:
    python app.py               # live capture
    python app.py --demo        # replay a simulated network (no privileges needed)
"""

from __future__ import annotations

import argparse
import sys
import time as _time

from PySide6.QtWidgets import QApplication

from linksight.ui.theme import apply
from linksight.ui.controller import AppController
from linksight.ui.main_window import MainWindow
from linksight.ui.splash import SplashScreen


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


def _version_suffix() -> str:
    """Short build SHA for the splash line, when available."""
    try:
        from linksight import version as vmod
        sha = getattr(vmod, "__version_sha__", "") or ""
        return sha[:8] if sha else ""
    except Exception:
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="linksight", description="LLDP/CDP neighbor discovery")
    parser.add_argument("--demo", action="store_true", help="replay simulated frames (no capture privileges needed)")
    args = parser.parse_args(argv)

    _set_windows_app_id()
    app = QApplication(sys.argv[:1])
    app.setApplicationName("LinkSight")
    apply(app)

    shot_mode = "--shot" in sys.argv

    # Launch splash: shown while the window boots, fed by MainWindow's
    # init_hook milestones. Skipped in screenshot mode.
    splash: SplashScreen | None = None
    if not shot_mode:
        suffix = _version_suffix()
        demo_note = " · demo mode" if args.demo else ""
        splash = SplashScreen(subtitle=f"LLDP/CDP Neighbor Discovery  ·  {suffix}{demo_note}" if suffix else "LLDP/CDP Neighbor Discovery")
        splash.set_status("Initializing…", 5)
        splash.show_centered()
        app.processEvents()

    def _init_hook(text: str, pct: int) -> None:
        if splash is not None:
            splash.set_status(text, pct)
            app.processEvents()

    controller = AppController()
    window = MainWindow(controller, demo=args.demo, init_hook=_init_hook if splash else None)

    if splash is not None:
        splash.set_status("Ready", 100)
        # Hold the splash a beat so the launch reads as deliberate, then hand
        # over to the main window.
        deadline = _time.monotonic() + 0.6
        while _time.monotonic() < deadline:
            app.processEvents()
            _time.sleep(0.01)
        window.show()
        splash.close()
    else:
        window.show()

    # For offscreen screenshot mode: --shot FILE exits after rendering
    if shot_mode:
        idx = sys.argv.index("--shot")
        shot_path = sys.argv[idx + 1]
        window.grab().save(shot_path)
        print(f"screenshot saved: {shot_path}")
        controller.close()
        return 0

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

