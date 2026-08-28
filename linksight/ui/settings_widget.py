"""Settings dialog — Npcap status and protocol toggles."""

from __future__ import annotations

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QFormLayout,
                               QPushButton, QLabel, QCheckBox, QHBoxLayout,
                               QGroupBox)

from ..capture import npcap
from .theme import OK, DANGER


class SettingsWidget(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        cap_group = QGroupBox("Protocols")
        form = QFormLayout(cap_group)
        form.setSpacing(8)

        self.ll_check = QCheckBox("Listen for LLDP (802.1AB)")
        self.ll_check.setChecked(True)
        self.cdp_check = QCheckBox("Listen for CDP (Cisco)")
        self.cdp_check.setChecked(True)
        form.addRow("", self.ll_check)
        form.addRow("", self.cdp_check)
        layout.addWidget(cap_group)

        # Npcap status row — Windows only
        np_group = QGroupBox("Windows capture driver")
        np_form = QFormLayout(np_group)
        np_form.setSpacing(8)
        self.npcap_status = QLabel()
        self.npcap_install_btn = QPushButton("Install Npcap…")
        self.npcap_install_btn.setVisible(False)
        self.npcap_install_btn.clicked.connect(self._install_npcap)
        self.npcap_check_btn = QPushButton("Check again")
        self.npcap_check_btn.setVisible(False)
        self.npcap_check_btn.clicked.connect(self._update_npcap_status)
        self._update_npcap_status()
        np_form.addRow("Npcap", self.npcap_status)
        row = QHBoxLayout()
        row.addWidget(self.npcap_install_btn)
        row.addWidget(self.npcap_check_btn)
        row.addStretch(1)
        np_form.addRow("", row)
        layout.addWidget(np_group)

        layout.addStretch(1)

    # ── Npcap ──

    def _update_npcap_status(self) -> None:
        status = npcap.npcap_installed()
        if status is None:
            self.npcap_status.setVisible(False)
            self.npcap_install_btn.setVisible(False)
            self.npcap_check_btn.setVisible(False)
            return
        if status:
            self.npcap_status.setText("installed")
            self.npcap_status.setStyleSheet(f"color: {OK};")
            self.npcap_install_btn.setVisible(False)
            self.npcap_check_btn.setVisible(False)
        else:
            self.npcap_status.setText("NOT DETECTED — required for capture")
            self.npcap_status.setStyleSheet(f"color: {DANGER};")
            self.npcap_install_btn.setVisible(True)
            self.npcap_check_btn.setVisible(True)

    def _install_npcap(self) -> None:
        import sys

        if sys.platform != "win32":
            return
        from PySide6.QtWidgets import QMessageBox, QProgressDialog, QApplication

        progress = QProgressDialog("Downloading Npcap installer…", "Cancel", 0, 0, self)
        progress.setWindowModality(2)  # ApplicationModal
        progress.setMinimumDuration(0)
        progress.show()
        QApplication.processEvents()
        try:
            path = npcap.download_installer()
        except Exception as e:
            progress.close()
            QMessageBox.warning(
                self,
                "LinkSight — Download failed",
                f"Could not download the Npcap installer.\n\n{e}\n\n"
                f"Download it manually from {npcap.NPCAP_DOWNLOAD_PAGE}",
            )
            return
        progress.close()
        # re-check: maybe it installed while we were downloading
        if npcap.npcap_installed():
            self._update_npcap_status()
            return
        ret = QMessageBox.question(
            self,
            "LinkSight — Npcap installer ready",
            "The Npcap installer has been downloaded.\n\n"
            "Launch it now? You'll see a UAC prompt — allow it, then "
            "walk through the installer (defaults are fine).\n\n"
            f"Installer: {path}",
        )
        if ret == QMessageBox.StandardButton.Yes:
            npcap.launch_installer(path)
        QMessageBox.information(
            self,
            "LinkSight — After installing",
            "When the installer finishes, click 'Check again' to verify, "
            "then restart LinkSight if it still shows not detected.",
        )

