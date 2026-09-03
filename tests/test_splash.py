"""Tests for the launch splash screen and MainWindow init-hook milestones."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from linksight.ui.controller import AppController
from linksight.ui.main_window import MainWindow
from linksight.ui.splash import SplashScreen


def test_splash_status_updates():
    """set_status drives both the status line and the progress bar."""
    app = QApplication.instance() or QApplication([])
    splash = SplashScreen(subtitle="LLDP/CDP Neighbor Discovery")
    try:
        splash.set_status("Starting capture engine…", 70)
        assert "Starting capture engine" in splash.status_label.text()
        assert splash.progress.value() == 70
        splash.set_status("Ready", 100)
        assert splash.progress.value() == 100
    finally:
        splash.close()


def test_splash_clamps_progress():
    app = QApplication.instance() or QApplication([])
    splash = SplashScreen()
    try:
        splash.set_status("Weird", -5)
        assert splash.progress.value() == 0
        splash.set_status("Weird", 150)
        assert splash.progress.value() == 100
    finally:
        splash.close()


def test_main_window_init_hook_reports_ascending_stages():
    """MainWindow construction reports launch milestones through init_hook in
    strictly ascending progress order, ending at the watcher stage."""
    app = QApplication.instance() or QApplication([])
    controller = AppController()
    stages: list[tuple[str, int]] = []
    window = MainWindow(controller, demo=True, init_hook=lambda t, p: stages.append((t, p)))
    try:
        assert len(stages) >= 3
        pcts = [p for _, p in stages]
        assert pcts == sorted(pcts)
        assert stages[-1][0] == "Loading interface monitor…"
        assert stages[-1][1] <= 95
    finally:
        controller.close()
        window.close()
