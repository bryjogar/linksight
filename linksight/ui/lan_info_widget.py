"""LAN info panel — the attached network's identity (adapter config + DHCP)."""

from __future__ import annotations

import threading
import time
from PySide6.QtCore import Qt, Signal, QTimer, QThread
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel,
                               QGroupBox, QSizePolicy)

from ..capture.system_info import (
    get_interface_config,
    get_quick_interface_config,
    InterfaceConfig,
)
from ..capture.oui_lookup import lookup_vendor
from .theme import FG, FG_DIM, FG_FAINT, ACCENT, MONO


def _row(label: str, value: str):
    lbl = QLabel(label)
    lbl.setStyleSheet(f"color: {FG_DIM}; font-weight: 500;")
    val = QLabel(value if value else "—")
    val.setTextInteractionFlags(Qt.TextSelectableByMouse)
    val.setObjectName("mono")
    val.setWordWrap(True)
    if value:
        val.setStyleSheet(f"color: {ACCENT}; font-family: {MONO}; font-weight: 600;")
    else:
        val.setStyleSheet(f"color: {FG_FAINT}; font-family: {MONO};")
    return lbl, val


class InterfaceConfigWorker(QThread):
    """Background worker thread for fetching interface configuration without blocking UI."""

    finished = Signal(object)  # InterfaceConfig
    cancelled = Signal()

    def __init__(self, iface_name: str, parent=None):
        super().__init__(parent)
        self.iface_name = iface_name
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    @property
    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def run(self) -> None:
        if self._stop_event.is_set():
            self.cancelled.emit()
            return
        cfg = get_interface_config(self.iface_name)
        if self._stop_event.is_set():
            self.cancelled.emit()
            return
        self.finished.emit(cfg)


class LanInfoWidget(QWidget):
    config_updated = Signal(object)

    def __init__(self, controller=None, parent=None):
        super().__init__(parent)
        self._iface_name = ""
        self._mac_override = ""
        self.controller = controller  # set by main_window for DHCP observation
        self._cached_cfg: InterfaceConfig | None = None
        self._worker: InterfaceConfigWorker | None = None
        self._last_bg_completed: float = 0.0
        self._pending_refresh: bool = False
        self._min_interval: float = 1.5

        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.timeout.connect(self._start_bg_worker)

        self.group = QGroupBox("LAN Info")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.group)
        # hug content vertically — no dead space below the rows
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)

        self.grid = QGridLayout(self.group)
        self.grid.setHorizontalSpacing(24)
        self.grid.setVerticalSpacing(2)
        self.grid.setContentsMargins(2, 0, 2, 4)

    def set_interface(self, iface_name: str, mac: str = "") -> None:
        if self._iface_name != iface_name or self._cached_cfg is None:
            self._iface_name = iface_name
            self._mac_override = mac
            # Initial render: psutil-level data (fast, no subprocess)
            self._cached_cfg = get_quick_interface_config(iface_name) if iface_name else None
            if self._cached_cfg and mac and not self._cached_cfg.mac:
                self._cached_cfg.mac = mac
            self._render_current()
            # Kick background fetch to enrich with ipconfig/DHCP details
            self._request_bg_refresh(immediate=True)
        else:
            if mac and self._mac_override != mac:
                self._mac_override = mac
                if self._cached_cfg and not self._cached_cfg.mac:
                    self._cached_cfg.mac = mac
            self._render_current()

    def refresh(self) -> None:
        """Render from cached data immediately, then request debounced background refresh."""
        if self._cached_cfg is None and self._iface_name:
            self._cached_cfg = get_quick_interface_config(self._iface_name)
            if self._mac_override and not self._cached_cfg.mac:
                self._cached_cfg.mac = self._mac_override
        self._render_current()
        self._request_bg_refresh(immediate=False)

    def _request_bg_refresh(self, immediate: bool = False) -> None:
        if not self._iface_name:
            return

        if self._worker is not None and self._worker.isRunning():
            self._pending_refresh = True
            return

        now = time.monotonic()
        elapsed = now - self._last_bg_completed

        if immediate or elapsed >= self._min_interval:
            self._debounce_timer.stop()
            self._start_bg_worker()
        else:
            remaining_ms = int(max(100, (self._min_interval - elapsed) * 1000))
            if not self._debounce_timer.isActive():
                self._debounce_timer.start(remaining_ms)

    def _start_bg_worker(self) -> None:
        if not self._iface_name:
            return
        if self._worker is not None and self._worker.isRunning():
            self._pending_refresh = True
            return

        self._worker = InterfaceConfigWorker(self._iface_name, parent=self)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.cancelled.connect(self._on_worker_cancelled)
        self._worker.start()

    def _on_worker_finished(self, cfg: InterfaceConfig) -> None:
        self._last_bg_completed = time.monotonic()
        if cfg and cfg.name == self._iface_name:
            self._cached_cfg = cfg
            self._render_current()
            self.config_updated.emit(cfg)

        self._worker = None

        if self._pending_refresh:
            self._pending_refresh = False
            self._debounce_timer.start(int(self._min_interval * 1000))

    def _on_worker_cancelled(self) -> None:
        self._worker = None

        if self._pending_refresh:
            self._pending_refresh = False
            self._debounce_timer.start(int(self._min_interval * 1000))

    def _render_current(self) -> None:
        cfg = self._cached_cfg
        net = self.controller.network if self.controller else {}

        mac = self._mac_override or (cfg.mac if cfg else "")
        vendor = lookup_vendor(mac) if mac else ""
        mac_display = mac if mac else ""
        if mac and vendor:
            mac_display = f"{mac}  ({vendor})"

        dhcp_server = cfg.dhcp_server if cfg and cfg.dhcp_server else net.get("server_ip", "")
        rows = [
            ("IP address", cfg.ip if cfg else ""),
            ("Subnet mask", cfg.netmask if cfg else ""),
            ("Default gateway", cfg.gateway if cfg else ""),
            ("DNS servers", ", ".join(cfg.dns_servers) if cfg else ""),
            ("DHCP server", dhcp_server),
            ("DHCP enabled", ("yes" if cfg.dhcp_enabled else "no") if cfg and cfg.dhcp_enabled is not None else ""),
            ("MAC address", mac_display),
        ]
        if net.get("last_message"):
            rows.append(("DHCP observed", net.get("last_message", "")))
        if net.get("domain"):
            rows.append(("Domain", net.get("domain", "")))

        self._render(rows)

    def _render(self, rows) -> None:
        self._clear_grid()
        for i, (label, value) in enumerate(rows):
            lbl, val = _row(label, value)
            self.grid.addWidget(lbl, i, 0)
            self.grid.addWidget(val, i, 1)
        self.grid.setColumnStretch(1, 1)

    def _clear_grid(self) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def closeEvent(self, event) -> None:
        if self._debounce_timer.isActive():
            self._debounce_timer.stop()
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(2000)
        super().closeEvent(event)
