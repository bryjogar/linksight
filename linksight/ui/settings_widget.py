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
        from PySide6.QtCore import Qt, QThread, Signal
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl
        from PySide6.QtWidgets import QMessageBox, QProgressDialog

        # Download runs off the UI thread so the dialog stays responsive and a
        # slow/stalled link can't freeze the app. The worker emits (path, error).
        class _DownloadWorker(QThread):
            done = Signal(object, object)  # (path_or_None, error_or_None)

            def run(self) -> None:
                try:
                    path = npcap.download_installer(timeout=60.0)
                    self.done.emit(path, None)
                except Exception as exc:  # noqa: BLE001 — surfaced to the user
                    self.done.emit(None, exc)

        progress = QProgressDialog("Downloading Npcap installer…", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.ApplicationModal)
        progress.setMinimumDuration(0)
        progress.setCancelButton(None)  # short download; avoid a half-written file
        progress.show()

        worker = _DownloadWorker(self)

        def _on_done(path, error):
            progress.close()
            worker.deleteLater()
            if error is not None:
                _show_failure(str(error))
                return
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

        def _show_failure(reason: str) -> None:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("LinkSight — Npcap download failed")
            box.setText(
                "Could not download the Npcap installer automatically.\n\n"
                f"{reason}\n\n"
                "You can open the official download page in your browser "
                "and install Npcap manually — it is a free, standard "
                "Windows packet-capture driver."
            )
            open_btn = box.addButton("Open download page", QMessageBox.ButtonRole.ActionRole)
            box.addButton(QMessageBox.StandardButton.Close)
            box.exec()
            if box.clickedButton() is open_btn:
                QDesktopServices.openUrl(QUrl(npcap.NPCAP_DOWNLOAD_PAGE))

        worker.done.connect(_on_done)
        worker.start()

