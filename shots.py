#!/usr/bin/env python3
"""Render LinkSight main window to PNGs (offscreen) for review. Usage: python shots.py OUTDIR"""

import sys
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from linksight.ui.theme import apply
from linksight.ui.controller import AppController
from linksight.ui.main_window import MainWindow

outdir = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/linksight-shots")
outdir.mkdir(parents=True, exist_ok=True)

app = QApplication(sys.argv[:1])
app.setApplicationName("LinkSight")
apply(app)

controller = AppController()
window = MainWindow(controller, demo=True)
window.show()


def snap():
    # select the first non-loopback NIC so LAN info populates
    try:
        for row in range(window.nic_widget.model.rowCount()):
            nic = window.nic_widget.model.nic_at(row)
            if nic and not nic.is_loopback:
                window.nic_widget.table.selectRow(row)
                break
    except Exception:
        pass
    # show the raw frame feed in the shot
    window.feed_widget.setVisible(True)
    app.processEvents()
    path = outdir / "linksight_main.png"
    window.grab().save(str(path))
    print(str(path))
    controller.close()
    app.quit()


QTimer.singleShot(8000, snap)
app.exec()

