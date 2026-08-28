"""Main window — clean readout: NIC status, LAN info, switch info."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QSize, QEvent, QTimer
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QMessageBox, QLabel,
                               QPushButton, QComboBox, QStatusBar,
                               QDialog)

from .controller import AppController
from .nic_status_widget import NicStatusWidget
from .lan_info_widget import LanInfoWidget
from .switch_info_widget import SwitchInfoWidget
from .feed_widget import FeedWidget
from .settings_widget import SettingsWidget

from ..capture.interfaces import list_interfaces, preferred_interface
from ..capture.sniffer import Sniffer
from ..capture.demo import DemoSource
from .ssh_terminal import launch_ssh_terminal
from .update_event import UpdateAvailableEvent


class MainWindow(QMainWindow):
    def __init__(self, controller: AppController, demo: bool = False):
        super().__init__()
        self.controller = controller
        self.demo = demo
        self.setWindowTitle("NetProbe — LLDP/CDP Neighbor Discovery")
        self.setWindowIcon(self._app_icon())
        self.setMinimumSize(1080, 720)
        self.resize(1280, 840)

        self._setup_ui()
        self._setup_statusbar()

        # wiring
        self.controller.device_seen.connect(self._on_device)
        self.controller.dhcp_seen.connect(self._on_dhcp)
        self.controller.capture_error.connect(self._on_capture_error)
        self.nic_widget.selection_changed.connect(self._on_nic_selected)
        self.iface_combo.currentIndexChanged.connect(self._on_iface_changed)
        self.switch_widget.ssh_requested.connect(self._on_ssh_requested)

        # seed LAN info with the preferred interface
        preferred = self.iface_combo.currentData()
        if preferred:
            mac = ""
            for nic in self.interfaces:
                if nic.name == preferred:
                    mac = nic.mac
                    break
            self.lan_widget.set_interface(preferred, mac)

        # capture starts automatically
        self._start()

    # ── UI construction ──

    @staticmethod
    def _app_icon():
        """Resolve app icon (works in dev and PyInstaller bundles)."""
        import os
        from PySide6.QtGui import QIcon

        candidates = []
        if getattr(sys, "frozen", False):
            candidates.append(os.path.join(sys._MEIPASS, "netprobe.ico"))
        candidates.append(
            os.path.join(os.path.dirname(__file__), "..", "..", "netprobe.ico")
        )
        candidates.append(
            os.path.join(os.path.dirname(sys.executable), "netprobe.ico")
            if getattr(sys, "frozen", False) else ""
        )
        for path in candidates:
            if path and os.path.exists(path):
                return QIcon(path)
        return QIcon()  # fallback — blank icon

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(4)

        # Top bar: interface picker + status (capture is always on)
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("Capture on:"))
        self.iface_combo = QComboBox()
        self.interfaces = list_interfaces()
        for nic in self.interfaces:
            self.iface_combo.addItem(nic.label(), nic.name)
        preferred = preferred_interface(self.interfaces)
        if preferred is not None:
            idx = self.iface_combo.findData(preferred.name)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
        self.iface_combo.setMinimumWidth(300)
        top_bar.addWidget(self.iface_combo)

        top_bar.addStretch(1)

        self.top_status = QLabel("Ready")
        self.top_status.setStyleSheet("color: #808080; font-size: 12px;")
        top_bar.addWidget(self.top_status)

        settings_btn = QPushButton("Settings")
        settings_btn.setObjectName("tool")
        settings_btn.clicked.connect(self._open_settings)
        top_bar.addWidget(settings_btn)

        main_layout.addLayout(top_bar)

        # Body: NIC status (top), LAN + Switch (side by side below)
        self.nic_widget = NicStatusWidget()
        self.nic_widget.setMaximumHeight(190)
        main_layout.addWidget(self.nic_widget)

        info_row = QHBoxLayout()
        info_row.setSpacing(4)
        self.lan_widget = LanInfoWidget()
        self.switch_widget = SwitchInfoWidget()
        info_row.addWidget(self.lan_widget, 1, Qt.AlignTop)
        info_row.addWidget(self.switch_widget, 1, Qt.AlignTop)
        main_layout.addLayout(info_row, stretch=1)

        # Raw frame feed (collapsed-ish, for debugging)
        self.feed_widget = FeedWidget()
        self.feed_widget.setMaximumHeight(200)
        self.feed_widget.setVisible(False)
        main_layout.addWidget(self.feed_widget)

        feed_toggle = QPushButton("Raw frames")
        feed_toggle.setObjectName("tool")
        feed_toggle.setCheckable(True)
        feed_toggle.toggled.connect(lambda on: self.feed_widget.setVisible(on))
        main_layout.addWidget(feed_toggle, alignment=Qt.AlignLeft)

    def _setup_statusbar(self):
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.status_left = QLabel("")
        self.status_left.setStyleSheet("color: #808080; padding: 2px 8px;")
        self.statusbar.addWidget(self.status_left)
        self.status_right = QLabel("")
        self.status_right.setStyleSheet("color: #808080; padding: 2px 8px;")
        self.statusbar.addPermanentWidget(self.status_right)
        # Clickable update notification (hidden until update available)
        self._status_update = QLabel("")
        self._status_update.setStyleSheet(
            "padding: 2px 8px; font-weight: 600;"
        )
        self._status_update.setOpenExternalLinks(True)
        self._status_update.hide()
        self.statusbar.addPermanentWidget(self._status_update)
        self._check_for_updates()

        # Re-check periodically so the update link appears without a restart
        self._update_timer = QTimer(self)
        self._update_timer.timeout.connect(self._check_for_updates)
        self._update_timer.start(15 * 60 * 1000)  # every 15 minutes

    def _open_settings(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("NetProbe Settings")
        dlg.setMinimumWidth(420)
        layout = QVBoxLayout(dlg)
        settings = SettingsWidget(self.controller)
        layout.addWidget(settings)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)
        dlg.exec()

    # ── capture (always on) ──

    def _start(self) -> None:
        if self.controller.source is not None:
            return  # already capturing
        if self.demo:
            self.controller.source = DemoSource(self.controller.on_device,
                                                self.controller.on_dhcp, interval=2.5)
            self.controller.source.start()
        else:
            iface = self.iface_combo.currentData()
            if not iface:
                QMessageBox.warning(self, "NetProbe", "No network interface available.")
                return
            if sys.platform == "win32":
                from ..capture import npcap
                if npcap.npcap_installed() is False:
                    ret = QMessageBox.warning(
                        self,
                        "NetProbe — Npcap required",
                        "Npcap is not installed. NetProbe needs it to capture "
                        "packets on Windows.\n\n"
                        "Install Npcap from Settings, or download it from npcap.com.",
                        QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
                    )
                    if ret != QMessageBox.StandardButton.Ok:
                        return
                    self._open_settings()
                    return
            self.controller.source = Sniffer(iface, self.controller.on_device,
                                             self.controller.on_error,
                                             self.controller.on_dhcp)
            self.controller.source.start()
        self.controller.capture_state_changed.emit(True)
        self.top_status.setText("Listening…" if not self.demo else "Replaying demo scenario…")

    def _on_iface_changed(self) -> None:
        """Restart capture on the newly selected interface (always-on)."""
        if self.controller.source is not None:
            self.controller.source.stop()
            self.controller.source = None
        self._start()
        # refresh LAN info for the new adapter
        nic = self.nic_widget.model.nic_at(self.nic_widget.table.currentRow()) \
            if self.nic_widget.table.currentRow() >= 0 else None
        if nic is not None:
            self.lan_widget.set_interface(nic.name, nic.mac)
        elif self.iface_combo.currentData():
            mac = ""
            for n in self.interfaces:
                if n.name == self.iface_combo.currentData():
                    mac = n.mac
                    break
            self.lan_widget.set_interface(self.iface_combo.currentData(), mac)

    # ── slots ──

    def _on_device(self, dev, raw=None) -> None:
        if raw is not None:
            self.feed_widget.add_frame(raw)
        self.switch_widget.show_device(dev)
        self.status_left.setText(
            f"Switch: {dev.system_name or dev.chassis_id}  ·  Port: "
            f"{(dev.raw_tlvs or {}).get('port_description') or dev.port_id or '?'}")

    def _on_dhcp(self, obs, raw=None) -> None:
        if raw is not None:
            self.feed_widget.add_frame(raw)
        self.lan_widget.refresh()
        self.status_right.setText(
            f"DHCP {obs.message_type} from {obs.server_ip or '?'}")

    def _on_nic_selected(self, nic) -> None:
        if nic is not None:
            self.lan_widget.set_interface(nic.name, nic.mac)

    def _on_ssh_requested(self, ip: str) -> None:
        """Ask for the SSH username (the terminal prompts for the password),
        then open a terminal running ssh — nothing is stored."""
        from PySide6.QtWidgets import QInputDialog

        username, ok = QInputDialog.getText(
            self, f"SSH to {ip}",
            "Username (the terminal will ask for the password):",
        )
        if not ok or not username.strip():
            return
        ok_launch, msg = launch_ssh_terminal(ip, username.strip())
        if not ok_launch:
            QMessageBox.warning(self, "NetProbe — SSH", msg)

    def _on_capture_error(self, msg: str) -> None:
        self.top_status.setText("Capture error")
        QMessageBox.critical(self, "NetProbe — Capture Error", msg)

    def _check_for_updates(self) -> None:
        """Check GitHub for a newer build — runs in background."""
        from threading import Thread

        from ..updater import check_for_updates

        try:
            from ..version import __version_sha__
        except ImportError:
            __version_sha__ = "unknown"

        # Only notify once — subsequent checks stay quiet after showing
        if getattr(self, "_update_shown", False):
            return

        def _run():
            info = check_for_updates(__version_sha__)
            if info:
                # Show update notification on main thread
                QApplication.instance().postEvent(
                    self, UpdateAvailableEvent(info)
                )

        Thread(target=_run, daemon=True).start()

    def event(self, event: QEvent) -> bool:
        """Handle custom events including UpdateAvailableEvent."""
        if event.type() == UpdateAvailableEvent._event_type:
            if getattr(self, "_update_shown", False):
                return True
            self._update_shown = True
            info = event.update_info
            self._status_update.setText(
                f'<a href="{info.url}" style="color: #60a5fa; text-decoration: underline;">'
                f'⬆ Update available: {info.current_sha} → {info.latest_sha}</a>'
                f' — {info.message[:60]}'
            )
            self._status_update.show()
            return True
        return super().event(event)

    def closeEvent(self, event):
        self.controller.close()
        super().closeEvent(event)
