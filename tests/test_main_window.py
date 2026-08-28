"""Regression tests for MainWindow and interface switching."""

import ctypes
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

for _egl in [
    "/opt/data/home/egl/usr/lib/x86_64-linux-gnu/libEGL.so.1",
    "/usr/lib/x86_64-linux-gnu/libEGL.so.1",
]:
    if os.path.exists(_egl):
        try:
            ctypes.CDLL(_egl, mode=ctypes.RTLD_GLOBAL)
            break
        except Exception:
            pass

from PySide6.QtWidgets import QApplication
from linksight.ui.controller import AppController
from linksight.ui.main_window import MainWindow


def test_on_iface_changed_no_crash():
    """Verify that switching interfaces does not crash with AttributeError on QTableView.currentRow."""
    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=True)
    try:
        # Directly call _on_iface_changed with default selection (or no selection)
        window._on_iface_changed()

        # If interfaces exist in the table, test with an active current index as well
        if window.nic_widget.model.rowCount() > 0:
            idx = window.nic_widget.model.index(0, 0)
            window.nic_widget.table.setCurrentIndex(idx)
            window._on_iface_changed()
    finally:
        controller.close()
        window.close()
