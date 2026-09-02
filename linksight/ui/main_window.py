"""Main window — clean readout: NIC status, LAN info, switch info, upstream path."""

from __future__ import annotations

import ipaddress
import sys
import time

from PySide6.QtCore import Qt, QSize, QEvent, QTimer, QThread, Signal
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QMessageBox, QLabel, QLineEdit,
                               QPushButton, QComboBox, QStatusBar,
                               QDialog, QInputDialog)

from .controller import AppController
from .nic_status_widget import NicStatusWidget
from .lan_info_widget import LanInfoWidget
from .switch_info_widget import SwitchInfoWidget
from .upstream_widget import UpstreamWidget
from .feed_widget import FeedWidget
from .settings_widget import SettingsWidget

from ..capture.interfaces import list_interfaces, preferred_interface, NetInterface
from ..capture.sniffer import Sniffer
from ..capture.demo import DemoSource
from .interface_watcher import InterfaceWatcher
from .ssh_terminal import launch_ssh_terminal
from .update_event import UpdateAvailableEvent


class UpstreamWorker(QThread):
    """Background worker thread for upstream discovery walks."""

    progress = Signal(str)
    finished = Signal(object)

    def __init__(self, start_ip: str, community: str, is_demo: bool = False, parent=None):
        super().__init__(parent)
        self.start_ip = start_ip
        # RAM-only community: kept strictly in memory for this worker
        self.community = community
        self.is_demo = is_demo

    def run(self) -> None:
        if self.is_demo:
            from ..discovery.demo import get_demo_path
            self.progress.emit(f"Querying hop 1: {self.start_ip} (Access-SW2)…")
            time.sleep(0.3)
            self.progress.emit("Querying hop 2: 10.0.0.2 (Core-SW1)…")
            time.sleep(0.3)
            self.progress.emit("STP Root reached. Querying edge firewall…")
            time.sleep(0.2)
            path = get_demo_path(self.start_ip)
            self.finished.emit(path)
        else:
            from ..discovery.walker import UpstreamWalker
            walker = UpstreamWalker(community=self.community)
            path = walker.walk(
                self.start_ip,
                progress_callback=lambda msg: self.progress.emit(msg),
            )
            self.finished.emit(path)


class ArpResolveWorker(QThread):
    """Background worker thread for resolving switch management IP via ARP."""

    finished = Signal(str)

    def __init__(self, dev, is_demo: bool = False, resolver=None, parent=None):
        super().__init__(parent)
        self.dev = dev
        self.is_demo = is_demo
        self.resolver = resolver

    def run(self) -> None:
        if self.is_demo:
            time.sleep(0.1)
            self.finished.emit("192.168.1.20")
            return

        if self.resolver is not None:
            resolved = self.resolver(self.dev)
        else:
            from ..discovery.arp_resolve import resolve_switch_mgmt_ip
            resolved = resolve_switch_mgmt_ip(self.dev)
        self.finished.emit(resolved or "")


class MainWindow(QMainWindow):
    def __init__(self, controller: AppController, demo: bool = False, state_provider=None):
        super().__init__()
        self.controller = controller
        self.demo = demo
        self._state_provider = state_provider
        self._session_community: str | None = None  # RAM-only process lifetime
        self._current_walk_ip: str = ""
        self._upstream_worker: UpstreamWorker | None = None
        self._arp_worker: ArpResolveWorker | None = None
        self._last_capture_error_time: float = 0.0

        self.setWindowTitle("LinkSight — LLDP/CDP Neighbor Discovery")
        self.setWindowIcon(self._app_icon())
        self.setMinimumSize(1080, 750)
        self.resize(1280, 880)

        self._setup_ui()
        self._setup_statusbar()

        # wiring
        self.controller.device_seen.connect(self._on_device)
        self.controller.dhcp_seen.connect(self._on_dhcp)
        self.controller.capture_error.connect(self._on_capture_error)
        self.nic_widget.selection_changed.connect(self._on_nic_selected)
        self.iface_combo.currentIndexChanged.connect(self._on_iface_changed)
        self.switch_widget.ssh_requested.connect(self._on_ssh_requested)
        self.switch_widget.upstream_requested.connect(self._on_upstream_requested)
        self.upstream_widget.refresh_requested.connect(self._on_upstream_refresh)

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

        # link-state and interface watcher
        self._setup_watcher()

    # ── UI construction ──

    @staticmethod
    def _app_icon():
        """Resolve app icon (works in dev and PyInstaller bundles)."""
        import os
        from PySide6.QtGui import QIcon

        candidates = []
        if getattr(sys, "frozen", False):
            candidates.append(os.path.join(sys._MEIPASS, "linksight.ico"))
        candidates.append(
            os.path.join(os.path.dirname(__file__), "..", "..", "linksight.ico")
        )
        candidates.append(
            os.path.join(os.path.dirname(sys.executable), "linksight.ico")
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
        self.lan_widget = LanInfoWidget(controller=self.controller)
        self.switch_widget = SwitchInfoWidget()
        info_row.addWidget(self.lan_widget, 1, Qt.AlignTop)
        info_row.addWidget(self.switch_widget, 1, Qt.AlignTop)
        main_layout.addLayout(info_row, stretch=0)

        # Upstream Discovery readout
        self.upstream_widget = UpstreamWidget()
        main_layout.addWidget(self.upstream_widget, stretch=1)

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
        dlg.setWindowTitle("LinkSight Settings")
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
                self.top_status.setText("No network interface available")
                self.top_status.setStyleSheet("color: #808080; font-size: 12px;")
                return
            if sys.platform == "win32":
                from ..capture import npcap
                if npcap.npcap_installed() is False:
                    ret = QMessageBox.warning(
                        self,
                        "LinkSight — Npcap required",
                        "Npcap is not installed. LinkSight needs it to capture "
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
        self.top_status.setStyleSheet("color: #808080; font-size: 12px;")
        self.top_status.setToolTip("")
        self.status_left.setText("")

    def _restart_capture(self) -> None:
        if self.demo:
            return
        if self.controller.source is not None:
            self.controller.source.stop()
            if hasattr(self.controller.source, "wait"):
                self.controller.source.wait(1.0)
            self.controller.source = None
        self._start()

    def _on_iface_changed(self) -> None:
        """Restart capture on the newly selected interface (always-on)."""
        if self.controller.source is not None:
            self.controller.source.stop()
            if hasattr(self.controller.source, "wait"):
                self.controller.source.wait(1.0)
            self.controller.source = None
        self._start()
        active = self.iface_combo.currentData() or ""
        if hasattr(self, "_watcher") and self._watcher is not None:
            self._watcher.set_active_interface(active)
        # refresh LAN info for the new adapter
        row = self.nic_widget.table.currentIndex().row()
        nic = self.nic_widget.model.nic_at(row) if row >= 0 else None
        if nic is not None:
            self.lan_widget.set_interface(nic.name, nic.mac)
        elif self.iface_combo.currentData():
            mac = ""
            for n in self.interfaces:
                if n.name == self.iface_combo.currentData():
                    mac = n.mac
                    break
            self.lan_widget.set_interface(self.iface_combo.currentData(), mac)

    def _setup_watcher(self) -> None:
        active_iface = self.iface_combo.currentData() or ""
        self._watcher = InterfaceWatcher(
            active_interface=active_iface,
            state_provider=self._state_provider,
            poll_interval_ms=2000,
            parent=self,
        )
        self._watcher.interfaces_changed.connect(self._on_interfaces_changed)
        self._watcher.capture_restart_needed.connect(self._on_capture_restart_needed)
        self._watcher.start()

    def _on_interfaces_changed(self, nics: list[NetInterface]) -> None:
        self.interfaces = nics
        # a. Update NIC table model in place (preserving selection)
        self.nic_widget.refresh(nics)

        # Update iface_combo items without resetting selection
        current = self.iface_combo.currentData()
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()
        for nic in self.interfaces:
            self.iface_combo.addItem(nic.label(), nic.name)
        if current:
            idx = self.iface_combo.findData(current)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
        self.iface_combo.blockSignals(False)

        # b. Refresh LAN info widget (non-blocking)
        self.lan_widget.refresh()

    def _on_capture_restart_needed(self, iface_name: str) -> None:
        if self.demo:
            return

        current = self.iface_combo.currentData()
        available_names = [nic.name for nic in self.interfaces]
        if not current or current not in available_names:
            # Active interface no longer exists; try switching to preferred
            preferred = preferred_interface(self.interfaces)
            if preferred is not None:
                idx = self.iface_combo.findData(preferred.name)
                if idx >= 0:
                    self.iface_combo.setCurrentIndex(idx)
                    return
            if self.controller.source is not None:
                self.controller.source.stop()
                if hasattr(self.controller.source, "wait"):
                    self.controller.source.wait(1.0)
                self.controller.source = None
            self.top_status.setText("No network interface available")
            return

        # Active interface recovered from down to up (debounced)
        self._restart_capture()

    # ── slots ──

    def _on_device(self, dev, raw=None) -> None:
        if raw is not None:
            self.feed_widget.add_frame(raw)
        self.switch_widget.show_device(dev)
        self.status_left.setText(
            f"Switch: {dev.system_name or dev.chassis_id}  ·  Port: "
            f"{(dev.raw_tlvs or {}).get('port_description') or dev.port_id or '?'}")

        # If switch did not advertise a management IP, auto-resolve from chassis MAC via ARP
        if not dev.management_ips and dev.chassis_id:
            self._start_arp_resolve(dev)

    def _start_arp_resolve(self, dev) -> None:
        if (self._arp_worker and self._arp_worker.isRunning()
                and getattr(self._arp_worker, "dev", None) == dev):
            return

        if self._arp_worker and self._arp_worker.isRunning():
            self._arp_worker.terminate()
            self._arp_worker.wait(500)

        self._arp_worker = ArpResolveWorker(dev, is_demo=self.demo, parent=self)
        self._arp_worker.finished.connect(self._on_arp_resolved)
        self._arp_worker.start()

    def _on_arp_resolved(self, resolved_ip: str) -> None:
        if resolved_ip:
            self.switch_widget.set_resolved_mgmt_ip(resolved_ip)

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
        username, ok = QInputDialog.getText(
            self, f"SSH to {ip}",
            "Username (the terminal will ask for the password):",
        )
        if not ok or not username.strip():
            return
        ok_launch, msg = launch_ssh_terminal(ip, username.strip())
        if not ok_launch:
            QMessageBox.warning(self, "LinkSight — SSH", msg)

    def _on_upstream_requested(self, start_ip: str) -> None:
        """Trigger an upstream discovery walk starting from start_ip."""
        if not start_ip:
            start_ip = self.switch_widget._current_mgmt_ip

        if not start_ip:
            if self.demo:
                start_ip = "10.0.0.3"
            else:
                prompt_label = (
                    "Switch Management IPv4 Address:\n"
                    "(Switch did not advertise a management IP via LLDP/CDP)"
                )
                while True:
                    ip_in, ok = QInputDialog.getText(
                        self,
                        "LinkSight — Upstream Discovery",
                        prompt_label,
                        QLineEdit.EchoMode.Normal,
                    )
                    if not ok or not ip_in.strip():
                        return
                    candidate = ip_in.strip()
                    try:
                        ipaddress.IPv4Address(candidate)
                        start_ip = candidate
                        break
                    except ValueError:
                        prompt_label = (
                            "Invalid IPv4 address. Please enter a valid switch management IPv4:"
                        )

            self.switch_widget.set_management_ip(start_ip)

        if self.demo:
            community = "public"
        else:
            if not self._session_community:
                community_in, ok = QInputDialog.getText(
                    self,
                    "LinkSight — Upstream Discovery",
                    f"SNMP Read Community (v2c) for {start_ip}:\n(Kept in memory for this session only, never saved)",
                    QLineEdit.EchoMode.Normal,
                    "public",
                )
                if not ok or not community_in.strip():
                    return
                self._session_community = community_in.strip()
            community = self._session_community

        self._current_walk_ip = start_ip
        self.upstream_widget.set_status(f"Starting discovery from {start_ip}…")
        self.controller.on_upstream_started(start_ip)

        self._upstream_worker = UpstreamWorker(start_ip, community, is_demo=self.demo, parent=self)
        self._upstream_worker.progress.connect(self._on_discovery_progress)
        self._upstream_worker.finished.connect(self._on_discovery_finished)
        self._upstream_worker.start()

    def _on_upstream_refresh(self) -> None:
        ip = self._current_walk_ip or self.switch_widget._current_mgmt_ip
        if ip:
            self._on_upstream_requested(ip)
        else:
            QMessageBox.information(
                self,
                "LinkSight — Upstream Discovery",
                "No active switch to discover.",
            )

    def _on_discovery_progress(self, msg: str) -> None:
        self.upstream_widget.set_status(msg)
        self.controller.on_upstream_progress(msg)

    def _on_discovery_finished(self, path) -> None:
        self.upstream_widget.show_path(path)
        self.controller.on_upstream_finished(path)

    def _on_capture_error(self, msg: str) -> None:
        now = time.monotonic()
        if now - getattr(self, "_last_capture_error_time", 0.0) < 5.0:
            return
        self._last_capture_error_time = now

        self.top_status.setText("Capture error")
        self.top_status.setStyleSheet("color: #ef4444; font-size: 12px;")
        self.top_status.setToolTip(msg)
        summary = msg.splitlines()[0] if msg else ""
        self.status_left.setText(f"Capture error: {summary}")
        self.statusbar.showMessage(f"Capture error: {summary}", 5000)

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
        if hasattr(self, "_watcher") and self._watcher is not None:
            self._watcher.stop()
        if self._upstream_worker and self._upstream_worker.isRunning():
            self._upstream_worker.terminate()
            self._upstream_worker.wait(1000)
        if self._arp_worker and self._arp_worker.isRunning():
            self._arp_worker.terminate()
            self._arp_worker.wait(1000)
        self.controller.close()
        super().closeEvent(event)
