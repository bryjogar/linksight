"""Main window — clean readout: NIC status, LAN info, switch info, upstream path."""

from __future__ import annotations

import ipaddress
import sys
import threading
import time
from typing import Callable, Any

from PySide6.QtCore import Qt, QSize, QEvent, QTimer, QThread, Signal
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QMessageBox, QLabel, QLineEdit,
                               QPushButton, QComboBox, QStatusBar,
                               QDialog, QInputDialog)

from .controller import AppController
from .lan_info_widget import LanInfoWidget
from .switch_info_widget import SwitchInfoWidget
from .upstream_widget import UpstreamWidget
from .feed_widget import FeedWidget
from .settings_widget import SettingsWidget

from ..capture.interfaces import list_interfaces, preferred_interface, wired_capture_interfaces, NetInterface
from ..capture.sniffer import Sniffer
from ..capture.demo import DemoSource
from ..discovery.models import PortDiagnostics
from ..discovery.arp_resolve import resolve_switch_mgmt_ip
from ..parse.model import NeighborDevice
from .interface_watcher import InterfaceWatcher
from .ssh_terminal import launch_ssh_terminal
from .update_event import UpdateAvailableEvent


class UpstreamWorker(QThread):
    """Background worker thread for upstream discovery walks."""

    progress = Signal(str)
    finished = Signal(object)
    cancelled = Signal()

    def __init__(
        self,
        start_ip: str,
        community: str,
        is_demo: bool = False,
        parent=None,
        forced_next_ip: str | None = None,
        endpoint_ip: str | None = None,
        endpoint_mac: str | None = None,
        forced_port_id: int | str | None = None,
        forced_hop_ip: str | None = None,
        forced_candidate: PortDiagnostics | None = None,
        no_ip_resolver: Callable[..., str | None] | None = None,
        endpoint_gateways: list[str] | None = None,
    ):
        super().__init__(parent)
        self.start_ip = start_ip
        # RAM-only community: kept strictly in memory for this worker
        self.community = community
        self.is_demo = is_demo
        self.forced_next_ip = forced_next_ip
        self.endpoint_ip = endpoint_ip
        self.endpoint_mac = endpoint_mac
        self.forced_port_id = forced_port_id
        self.forced_hop_ip = forced_hop_ip
        self.forced_candidate = forced_candidate
        self.no_ip_resolver = no_ip_resolver
        self.endpoint_gateways = endpoint_gateways or []
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    @property
    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def run(self) -> None:
        if self.is_demo:
            from ..discovery.demo import get_demo_path
            if self.forced_next_ip:
                self.progress.emit(f"Continuing discovery from {self.start_ip} via {self.forced_next_ip}…")
            else:
                self.progress.emit(f"Querying hop 1: {self.start_ip} (Access-SW2)…")
            for _ in range(30):
                if self._stop_event.is_set():
                    self.cancelled.emit()
                    return
                time.sleep(0.01)
            self.progress.emit("Querying hop 2: 10.0.0.2 (Core-SW1)…")
            for _ in range(30):
                if self._stop_event.is_set():
                    self.cancelled.emit()
                    return
                time.sleep(0.01)
            self.progress.emit("STP Root reached. Querying edge firewall…")
            for _ in range(20):
                if self._stop_event.is_set():
                    self.cancelled.emit()
                    return
                time.sleep(0.01)
            if self._stop_event.is_set():
                self.cancelled.emit()
                return
            path = get_demo_path(
                self.start_ip,
                forced_next_ip=self.forced_next_ip,
                endpoint_mac=self.endpoint_mac,
                forced_port_id=self.forced_port_id,
                forced_hop_ip=self.forced_hop_ip,
                forced_candidate=self.forced_candidate,
            )
            self.finished.emit(path)
        else:
            if self._stop_event.is_set():
                self.cancelled.emit()
                return
            from ..discovery.walker import UpstreamWalker
            walker = UpstreamWalker(community=self.community)
            path = walker.walk(
                self.start_ip,
                progress_callback=lambda msg: self.progress.emit(msg),
                stop_check=self._stop_event.is_set,
                forced_next_ip=self.forced_next_ip,
                endpoint_ip=self.endpoint_ip,
                endpoint_mac=self.endpoint_mac,
                forced_port_id=self.forced_port_id,
                forced_hop_ip=self.forced_hop_ip,
                forced_candidate=self.forced_candidate,
                resolve_no_ip_neighbor=self.no_ip_resolver,
                endpoint_gateways=self.endpoint_gateways,
            )
            if self._stop_event.is_set():
                self.cancelled.emit()
                return
            self.finished.emit(path)


class ArpResolveWorker(QThread):
    """Background worker thread for resolving switch management IP via ARP."""

    finished = Signal(str)
    cancelled = Signal()

    def __init__(self, dev, is_demo: bool = False, resolver=None, parent=None):
        super().__init__(parent)
        self.dev = dev
        self.is_demo = is_demo
        self.resolver = resolver
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    @property
    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def run(self) -> None:
        if self.is_demo:
            for _ in range(10):
                if self._stop_event.is_set():
                    self.cancelled.emit()
                    return
                time.sleep(0.01)
            if self._stop_event.is_set():
                self.cancelled.emit()
                return
            self.finished.emit("192.168.1.20")
            return

        if self._stop_event.is_set():
            self.cancelled.emit()
            return

        if self.resolver is not None:
            try:
                resolved = self.resolver(self.dev, stop_check=self._stop_event.is_set)
            except TypeError:
                resolved = self.resolver(self.dev)
        else:
            from ..discovery.arp_resolve import resolve_switch_mgmt_ip
            try:
                resolved = resolve_switch_mgmt_ip(self.dev, stop_check=self._stop_event.is_set)
            except TypeError:
                resolved = resolve_switch_mgmt_ip(self.dev)

        if self._stop_event.is_set():
            self.cancelled.emit()
            return

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
        self._pending_arp_dev = None
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
        self.iface_combo.currentIndexChanged.connect(self._on_iface_changed)
        self.switch_widget.ssh_requested.connect(self._on_ssh_requested)
        self.switch_widget.upstream_requested.connect(self._on_upstream_requested)
        self.upstream_widget.refresh_requested.connect(self._on_upstream_refresh)
        self.upstream_widget.continue_from.connect(self._on_upstream_continue)

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
        self._sync_capture_ui()

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

        # Top bar: interface picker + capture control + status
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("Capture on:"))
        self.iface_combo = QComboBox()
        self.interfaces = list_interfaces()
        for nic in wired_capture_interfaces(self.interfaces):
            self.iface_combo.addItem(nic.label(), nic.name)
        preferred = preferred_interface(self.interfaces)
        if preferred is not None:
            idx = self.iface_combo.findData(preferred.name)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
        self.iface_combo.setMinimumWidth(300)
        top_bar.addWidget(self.iface_combo)

        self.capture_btn = QPushButton()
        self.capture_btn.setObjectName("tool")
        self.capture_btn.setFixedWidth(120)
        self.capture_btn.clicked.connect(self._on_capture_toggle)
        top_bar.addWidget(self.capture_btn)

        top_bar.addStretch(1)

        self.top_status = QLabel("Ready")
        self.top_status.setStyleSheet("color: #808080; font-size: 12px;")
        top_bar.addWidget(self.top_status)

        settings_btn = QPushButton("Settings")
        settings_btn.setObjectName("tool")
        settings_btn.clicked.connect(self._open_settings)
        top_bar.addWidget(settings_btn)

        main_layout.addLayout(top_bar)

        # Body: LAN Info + Switch Info side by side; the capture dropdown in
        # the top bar defines which wired adapter is being monitored.
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

    # ── capture ──

    def _start(self) -> None:
        # A stale source object whose thread died must not block a restart.
        if self.controller.source is not None and self._capture_is_active():
            return  # already capturing
        iface: str = ""
        if self.demo:
            self.controller.source = DemoSource(self.controller.on_device,
                                                self.controller.on_dhcp, interval=2.5)
            self.controller.source.start()
        else:
            iface = self.iface_combo.currentData()
            if not iface:
                self.top_status.setText("No wired network interface available")
                self.top_status.setStyleSheet("color: #ef4444; font-size: 12px;")
                self._sync_capture_ui()
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
                    self._sync_capture_ui()
                    if ret != QMessageBox.StandardButton.Ok:
                        return
                    self._open_settings()
                    return
            if self.controller.source is not None:
                # Dead/stale source — retire it before starting fresh.
                try:
                    self.controller.source.stop()
                except Exception:
                    pass
                self.controller.source = None
            self.controller.source = Sniffer(
                iface,
                self.controller.on_device,
                self.controller.on_error,
                self.controller.on_dhcp,
                self.controller.on_permission_error,
            )
            self.controller.source.start()
        self.controller.capture_state_changed.emit(True)
        self.top_status.setText(
            "Replaying demo scenario…" if self.demo
            else f"Listening on {self.iface_combo.currentData() or iface}…"
        )
        self.top_status.setStyleSheet("color: #34d399; font-size: 12px;")
        self.top_status.setToolTip("")
        self.status_left.setText("")
        self._sync_capture_ui()

    def _capture_is_active(self) -> bool:
        if self.demo:
            return True
        src = self.controller.source
        if src is None:
            return False
        runner = getattr(src, "is_running", None)
        if callable(runner):
            try:
                return bool(runner())
            except Exception:
                return True
        return True

    def _sync_capture_ui(self) -> None:
        """Keep the Capture button and status honest about real capture state."""
        if self.demo:
            self.capture_btn.setText("Demo")
            self.capture_btn.setEnabled(False)
            return
        active = self._capture_is_active()
        self.capture_btn.setText("Stop capture" if active else "Start capture")
        self.capture_btn.setEnabled(self.iface_combo.count() > 0)
        if not active and self.iface_combo.count() == 0:
            self.top_status.setText("No wired network interface available")
            self.top_status.setStyleSheet("color: #ef4444; font-size: 12px;")

    def _on_capture_toggle(self) -> None:
        """Explicit start/stop — capture is not always-on anymore, and a dead
        capture is visible and restartable instead of a silent empty screen."""
        if self.demo:
            return
        if self._capture_is_active():
            if self.controller.source is not None:
                self.controller.source.stop()
                if hasattr(self.controller.source, "wait"):
                    self.controller.source.wait(1.0)
                self.controller.source = None
            self.controller.capture_state_changed.emit(False)
            self.top_status.setText("Capture stopped")
            self.top_status.setStyleSheet("color: #f59e0b; font-size: 12px;")
            self.status_left.setText("")
        else:
            self._start()
        self._sync_capture_ui()

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
        # refresh LAN info for the newly selected adapter
        name = self.iface_combo.currentData() or ""
        if name:
            mac = ""
            for n in self.interfaces:
                if n.name == name:
                    mac = n.mac
                    break
            self.lan_widget.set_interface(name, mac)

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

        # Update iface_combo items without resetting selection
        current = self.iface_combo.currentData()
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()
        for nic in wired_capture_interfaces(self.interfaces):
            self.iface_combo.addItem(nic.label(), nic.name)
        if current:
            idx = self.iface_combo.findData(current)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
        self.iface_combo.blockSignals(False)
        self._sync_capture_ui()

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
            self._pending_arp_dev = dev
            self._arp_worker.stop()
            return

        self._pending_arp_dev = None
        self._arp_worker = ArpResolveWorker(dev, is_demo=self.demo, parent=self)
        self._arp_worker.finished.connect(self._on_arp_resolved)
        self._arp_worker.cancelled.connect(self._on_arp_cancelled)
        self._arp_worker.start()

    def _on_arp_resolved(self, resolved_ip: str) -> None:
        self._arp_worker = None
        if resolved_ip and self._pending_arp_dev is None:
            self.switch_widget.set_resolved_mgmt_ip(resolved_ip)
        self._check_pending_arp()

    def _on_arp_cancelled(self) -> None:
        self._arp_worker = None
        self._check_pending_arp()

    def _check_pending_arp(self) -> None:
        if self._pending_arp_dev is not None:
            pending = self._pending_arp_dev
            self._pending_arp_dev = None
            self._start_arp_resolve(pending)

    def _on_dhcp(self, obs, raw=None) -> None:
        if raw is not None:
            self.feed_widget.add_frame(raw)
        self.lan_widget.refresh()
        self.status_right.setText(
            f"DHCP {obs.message_type} from {obs.server_ip or '?'}")

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

    def _on_upstream_requested(
        self,
        start_ip: str,
        forced_next_ip: str | None = None,
        forced_port_id: int | str | None = None,
        forced_hop_ip: str | None = None,
        forced_candidate: PortDiagnostics | None = None,
    ) -> None:
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
        if forced_next_ip:
            self.upstream_widget.set_status(f"Continuing discovery from {start_ip} via {forced_next_ip}…")
        else:
            self.upstream_widget.set_status(f"Starting discovery from {start_ip}…")
        self.controller.on_upstream_started(start_ip)

        if self._upstream_worker and self._upstream_worker.isRunning():
            self._upstream_worker.stop()
            self._upstream_worker.wait(1000)

        # Determine local endpoint MAC and IP from active capture interface
        endpoint_mac = None
        endpoint_ip = None
        active_iface = self.iface_combo.currentData() if hasattr(self, "iface_combo") else None
        if active_iface and hasattr(self, "interfaces"):
            for nic in self.interfaces:
                if nic.name == active_iface:
                    endpoint_mac = nic.mac
                    break
        if not endpoint_mac and hasattr(self, "lan_widget") and getattr(self.lan_widget, "_mac_override", None):
            endpoint_mac = self.lan_widget._mac_override
        if hasattr(self, "lan_widget") and getattr(self.lan_widget, "_cached_cfg", None):
            if not endpoint_mac and self.lan_widget._cached_cfg.mac:
                endpoint_mac = self.lan_widget._cached_cfg.mac
            if self.lan_widget._cached_cfg.ip:
                endpoint_ip = self.lan_widget._cached_cfg.ip

        if self.demo and not endpoint_mac:
            endpoint_mac = "aa:bb:cc:11:22:33"

        # Edge-device candidates: the DHCP-observed gateway(s) plus the OS
        # gateway read by the LAN Info panel (covers static config / no lease
        # traffic). Both point at the same physical edge in these networks.
        endpoint_gateways: list[str] = list(self.controller.network.get("gateways", []) or [])
        try:
            cfg = self.lan_widget._cached_cfg
            os_gw = (cfg.gateway or "").strip() if cfg else ""
            if os_gw and os_gw not in endpoint_gateways:
                endpoint_gateways.append(os_gw)
        except Exception:
            pass

        # Resolver for STP root-port neighbors that advertise no LLDP management IP.
        # Builds a NeighborDevice from the port's chassis MAC and ARP-resolves it,
        # exactly like the continuation-path resolver below (kept RAM-only, no state).
        def _no_ip_port_resolver(port: PortDiagnostics) -> str | None:
            chassis = port.neighbor_chassis if port else ""
            if not chassis:
                return None
            if self.demo:
                return "192.168.1.20"
            active = self.iface_combo.currentData() if hasattr(self, "iface_combo") else ""
            dev = NeighborDevice(
                protocol="lldp",
                source_interface=active or "",
                chassis_id=chassis,
                system_name=port.neighbor_name if port else "",
                management_ips=[],
            )
            try:
                return resolve_switch_mgmt_ip(dev)
            except Exception:
                return None

        self._upstream_worker = UpstreamWorker(
            start_ip,
            community,
            is_demo=self.demo,
            parent=self,
            forced_next_ip=forced_next_ip,
            endpoint_ip=endpoint_ip,
            endpoint_mac=endpoint_mac,
            forced_port_id=forced_port_id,
            forced_hop_ip=forced_hop_ip,
            forced_candidate=forced_candidate,
            no_ip_resolver=_no_ip_port_resolver,
            endpoint_gateways=endpoint_gateways,
        )
        self._upstream_worker.progress.connect(self._on_discovery_progress)
        self._upstream_worker.finished.connect(self._on_discovery_finished)
        self._upstream_worker.cancelled.connect(self._on_discovery_cancelled)
        self._upstream_worker.start()

    def _on_upstream_continue(self, target: Any) -> None:
        start_ip = self._current_walk_ip or self.switch_widget._current_mgmt_ip
        if not start_ip:
            return

        candidate: PortDiagnostics | None = None
        hop_ip: str | None = None
        port_id: int | str | None = None
        neighbor_ip: str = ""

        if isinstance(target, dict):
            candidate = target.get("candidate")
            hop_ip = target.get("hop_mgmt_ip") or target.get("hop_ip")
            port_id = target.get("port_id")
            if port_id is None and candidate:
                port_id = candidate.port_id
            if candidate and candidate.neighbor_ip:
                neighbor_ip = candidate.neighbor_ip
        elif isinstance(target, PortDiagnostics):
            candidate = target
            hop_ip = getattr(target, "_hop_ip", None)
            port_id = candidate.port_id
            neighbor_ip = candidate.neighbor_ip or ""
        elif isinstance(target, tuple):
            if len(target) > 0 and isinstance(target[0], PortDiagnostics):
                candidate = target[0]
                port_id = candidate.port_id
                neighbor_ip = candidate.neighbor_ip or ""
            if len(target) > 1 and isinstance(target[1], str):
                hop_ip = target[1]
        elif isinstance(target, str):
            neighbor_ip = target

        forced_hop_ip = hop_ip or start_ip
        forced_port_id = port_id

        # If candidate has an IP, continue with forced port identity
        if neighbor_ip:
            self._on_upstream_requested(
                start_ip,
                forced_next_ip=neighbor_ip,
                forced_port_id=forced_port_id,
                forced_hop_ip=forced_hop_ip,
                forced_candidate=candidate,
            )
            return

        # Candidate has NO IP: resolve management IP before walking
        chassis = candidate.neighbor_chassis if candidate else ""
        cand_name = (candidate.neighbor_name if candidate else "") or chassis or "neighbor switch"

        resolved_ip: str | None = None
        if self.demo:
            # Demo mode canned resolution for UniFi candidate
            resolved_ip = "192.168.1.20"
        elif chassis:
            active_iface = self.iface_combo.currentData() if hasattr(self, "iface_combo") else ""
            dev = NeighborDevice(
                protocol="lldp",
                source_interface=active_iface or "",
                chassis_id=chassis,
                system_name=candidate.neighbor_name if candidate else "",
                management_ips=[],
            )
            try:
                resolved_ip = resolve_switch_mgmt_ip(dev)
            except Exception:
                resolved_ip = None

        if resolved_ip:
            self._on_upstream_requested(
                start_ip,
                forced_next_ip=resolved_ip,
                forced_port_id=forced_port_id,
                forced_hop_ip=forced_hop_ip,
                forced_candidate=candidate,
            )
            return

        # ARP resolution failed or no chassis MAC: manual IP entry prompt fallback
        prompt_label = (
            f"Switch Management IPv4 Address for {cand_name}:\n"
            "(Switch did not advertise a management IP via LLDP/CDP and ARP resolution did not find it)"
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
            candidate_ip = ip_in.strip()
            try:
                ipaddress.IPv4Address(candidate_ip)
                self._on_upstream_requested(
                    start_ip,
                    forced_next_ip=candidate_ip,
                    forced_port_id=forced_port_id,
                    forced_hop_ip=forced_hop_ip,
                    forced_candidate=candidate,
                )
                break
            except ValueError:
                prompt_label = "Invalid IPv4 address. Please enter a valid switch management IPv4:"

    def _on_discovery_cancelled(self) -> None:
        self._upstream_worker = None

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
        self._maybe_prompt_for_stalled_hop(path)

    def _maybe_prompt_for_stalled_hop(self, path) -> None:
        """When the walk stops because the next switch is identifiable but has no
        reachable management IP (STP/LLDP pointed at it; SNMP/ARP failed), offer the
        same manual-IP modal used for the first walk so the engineer can type the
        address and continue instead of being stuck at a dead-end."""
        try:
            if not path or path.success or not path.hops:
                return
            if getattr(self, "demo", False):
                return
            last = path.hops[-1]
            # Only auto-prompt when there is exactly ONE clear next hop and it is
            # missing a usable IP — multi-candidate ambiguity keeps its buttons.
            if last.status not in ("ambiguous", "unreachable", "timeout"):
                return
            candidates = list(getattr(last, "ambiguous_candidates", None) or [])
            if len(candidates) != 1:
                # fall back: single uplink port whose neighbor has identity but no IP
                up = getattr(last, "uplink_port", None)
                if not up or not (up.neighbor_name or up.neighbor_chassis):
                    return
                cand = up
            else:
                cand = candidates[0]
            # The advertised IP(s) already failed (status unreachable/timeout);
            # offer manual entry regardless so the engineer can supply the
            # correct management address.
            name = cand.neighbor_name or cand.neighbor_chassis or "switch"
            port_id = cand.port_id
            # Skip auto-modal if this exact hop was already asked (avoid loops)
            ask_key = (getattr(last, "mgmt_ip", ""), port_id)
            if getattr(self, "_last_stall_prompt", None) == ask_key:
                return
            self._last_stall_prompt = ask_key
            prompt_label = (
                f"LinkSight could not reach the next switch: {name}.\n"
                "Its advertised management IP(s) did not respond.\n\n"
                "Enter the switch management IPv4 address to continue:"
            )
            ip_in, ok = QInputDialog.getText(
                self,
                "LinkSight — Continue upstream path",
                prompt_label,
                QLineEdit.EchoMode.Normal,
            )
            if not ok or not ip_in.strip():
                return
            candidate_ip = ip_in.strip()
            try:
                ipaddress.IPv4Address(candidate_ip)
            except ValueError:
                QMessageBox.warning(self, "LinkSight", "That is not a valid IPv4 address.")
                return
            hops_list = list(getattr(path, "hops", []) or [])
            # Resume from the LAST SUCCESSFUL hop: the one whose uplink points
            # at the switch we're trying to reach. Restarting from the original
            # start replays the same failing selection (forced_hop_ip never
            # matches) — the manual IP never gets used.
            resume_hop = None
            if len(hops_list) >= 2 and hops_list[-1].status in ("unreachable", "timeout", "auth_failed"):
                resume_hop = hops_list[-2]
            start_ip = (
                (resume_hop.mgmt_ip if resume_hop and resume_hop.mgmt_ip else "")
                or (getattr(self, "_current_walk_ip", "") or self.switch_widget._current_mgmt_ip)
            )
            if not start_ip:
                return
            self._on_upstream_requested(
                start_ip,
                forced_next_ip=candidate_ip,
                forced_port_id=port_id,
                forced_hop_ip=(resume_hop.mgmt_ip if resume_hop else last.mgmt_ip),
                forced_candidate=cand,
            )
        except Exception:
            # The prompt is convenience — never let it disrupt the finished path view
            pass

    def _on_capture_error(self, msg: str, permission: bool = False) -> None:
        now = time.monotonic()
        if now - getattr(self, "_last_capture_error_time", 0.0) < 5.0:
            return
        self._last_capture_error_time = now

        summary = msg.splitlines()[0] if msg else ""
        if permission:
            # Actionable: the user's fix is to relaunch elevated, not to
            # decipher a driver error. First line already carries the action.
            self.top_status.setText("Capture blocked")
            self.status_left.setText(summary or "Unable to capture - run LinkSight as Administrator")
            self.statusbar.showMessage(summary or "Unable to capture", 8000)
        else:
            self.top_status.setText("Capture error")
            self.status_left.setText(f"Capture error: {summary}")
            self.statusbar.showMessage(f"Capture error: {summary}", 5000)
        self.top_status.setStyleSheet("color: #ef4444; font-size: 12px;")
        self.top_status.setToolTip(msg)
        self._sync_capture_ui()

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
            self._upstream_worker.stop()
            self._upstream_worker.wait(2000)
        if self._arp_worker and self._arp_worker.isRunning():
            self._arp_worker.stop()
            self._arp_worker.wait(2000)
        self.controller.close()
        super().closeEvent(event)
