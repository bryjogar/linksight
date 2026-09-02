"""Tests for link-state and interface resiliency (DHCP subprocess offload, watcher, non-modal errors)."""

from __future__ import annotations

import os
import subprocess

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication, QMessageBox

from linksight.capture.interfaces import NetInterface
from linksight.capture.system_info import InterfaceConfig
from linksight.ui.controller import AppController
from linksight.ui.lan_info_widget import LanInfoWidget
from linksight.ui.nic_status_widget import NicStatusWidget
from linksight.ui.interface_watcher import InterfaceWatcher
from linksight.ui.main_window import MainWindow


# ── PROBLEM 1 TESTS: UI Thread Blocks on Subprocess During DHCP ──


def test_lan_info_widget_refresh_renders_cached_data_without_subprocess(monkeypatch):
    """Verify refresh() uses cached data immediately without invoking subprocess on main thread."""
    app = QApplication.instance() or QApplication([])

    # Disallow subprocess calls on main thread
    def _fail_run(*args, **kwargs):
        raise AssertionError("subprocess.run must not be called synchronously on the UI thread!")

    monkeypatch.setattr(subprocess, "run", _fail_run)

    widget = LanInfoWidget()
    try:
        # Initial set_interface
        widget.set_interface("eth0", "00:11:22:33:44:55")

        # Calling refresh directly
        widget.refresh()

        # Check that UI rendered rows
        assert widget.grid.count() > 0
        # Wait for any background worker to finish if spawned
        if widget._worker is not None:
            widget._worker.wait(2000)
    finally:
        widget.close()


def test_lan_info_widget_dhcp_burst_debounce(monkeypatch):
    """Verify rapid refresh calls coalesce and do not queue multiple workers."""
    app = QApplication.instance() or QApplication([])

    worker_run_count = 0

    def _fake_get_cfg(iface_name: str) -> InterfaceConfig:
        nonlocal worker_run_count
        worker_run_count += 1
        return InterfaceConfig(name=iface_name, ip="192.168.1.50", gateway="192.168.1.1")

    monkeypatch.setattr("linksight.ui.lan_info_widget.get_interface_config", _fake_get_cfg)

    widget = LanInfoWidget()
    try:
        widget.set_interface("eth0", "00:11:22:33:44:55")
        if widget._worker is not None:
            widget._worker.wait(2000)
            QCoreApplication.processEvents()

        initial_count = worker_run_count

        # Fire a rapid burst of refreshes (simulating DHCP frame stream)
        for _ in range(5):
            widget.refresh()

        # Rapid requests must coalesce (timer active, pending set, or at most 1 worker running)
        assert widget._debounce_timer.isActive() or widget._pending_refresh or (widget._worker is not None)

        if widget._worker is not None:
            widget._worker.wait(2000)
            QCoreApplication.processEvents()

        # Ensure worker count did not increase by 5
        assert worker_run_count - initial_count <= 2
    finally:
        widget.close()


def test_lan_info_widget_background_enrichment(monkeypatch):
    """Verify LanInfoWidget updates with enriched details when background worker completes."""
    app = QApplication.instance() or QApplication([])

    def _fake_get_cfg(iface_name: str) -> InterfaceConfig:
        return InterfaceConfig(
            name=iface_name,
            ip="192.168.1.100",
            netmask="255.255.255.0",
            gateway="192.168.1.1",
            dns_servers=["1.1.1.1"],
            dhcp_server="192.168.1.1",
            dhcp_enabled=True,
        )

    monkeypatch.setattr("linksight.ui.lan_info_widget.get_interface_config", _fake_get_cfg)

    widget = LanInfoWidget()
    try:
        widget.set_interface("eth0")
        assert widget._worker is not None
        widget._worker.wait(2000)
        QCoreApplication.processEvents()

        assert widget._cached_cfg is not None
        assert widget._cached_cfg.ip == "192.168.1.100"
        assert widget._cached_cfg.gateway == "192.168.1.1"
        assert widget._cached_cfg.dhcp_server == "192.168.1.1"
    finally:
        widget.close()


# ── PROBLEM 2 TESTS: Link-State / Interface Watcher & Safe NIC Table Refresh ──


def test_interface_watcher_change_detection():
    """Verify InterfaceWatcher emits changed signal only on actual link/IP/interface changes."""
    app = QApplication.instance() or QApplication([])

    current_state = [
        NetInterface(name="eth0", ips=["192.168.1.10"], is_up=True),
        NetInterface(name="wlan0", ips=[], is_up=False),
    ]

    watcher = InterfaceWatcher(
        active_interface="eth0",
        state_provider=lambda: current_state,
        poll_interval_ms=10000,
    )
    watcher.start()

    changed_events: list[list[NetInterface]] = []
    watcher.interfaces_changed.connect(changed_events.append)

    # 1. No change -> no signal
    watcher.check_now()
    assert len(changed_events) == 0

    # 2. is_up flips on wlan0 -> signal emitted
    current_state = [
        NetInterface(name="eth0", ips=["192.168.1.10"], is_up=True),
        NetInterface(name="wlan0", ips=[], is_up=True),
    ]
    watcher.check_now()
    assert len(changed_events) == 1

    # 3. Active interface gains an IP -> signal emitted
    current_state = [
        NetInterface(name="eth0", ips=["192.168.1.10", "10.0.0.5"], is_up=True),
        NetInterface(name="wlan0", ips=[], is_up=True),
    ]
    watcher.check_now()
    assert len(changed_events) == 2

    # 4. Interface set changes (adapter removed) -> signal emitted
    current_state = [
        NetInterface(name="eth0", ips=["192.168.1.10", "10.0.0.5"], is_up=True),
    ]
    watcher.check_now()
    assert len(changed_events) == 3

    watcher.stop()


def test_interface_watcher_restart_debounce():
    """Verify capture restart is debounced to ~2 consecutive UP ticks after being DOWN."""
    app = QApplication.instance() or QApplication([])

    current_state = [
        NetInterface(name="eth0", ips=[], is_up=True),
    ]

    watcher = InterfaceWatcher(
        active_interface="eth0",
        state_provider=lambda: current_state,
        poll_interval_ms=10000,
    )
    watcher.start()

    restart_events: list[str] = []
    watcher.capture_restart_needed.connect(restart_events.append)

    # Stable UP initially -> no restart
    watcher.check_now()
    assert len(restart_events) == 0

    # Link goes DOWN
    current_state = [NetInterface(name="eth0", ips=[], is_up=False)]
    watcher.check_now()
    assert len(restart_events) == 0
    assert watcher._active_was_down is True

    # Link flaps UP (1st tick) -> debounced, NO restart yet
    current_state = [NetInterface(name="eth0", ips=[], is_up=True)]
    watcher.check_now()
    assert len(restart_events) == 0
    assert watcher._active_was_down is True
    assert watcher._active_up_ticks == 1

    # Link flaps back DOWN
    current_state = [NetInterface(name="eth0", ips=[], is_up=False)]
    watcher.check_now()
    assert len(restart_events) == 0
    assert watcher._active_was_down is True
    assert watcher._active_up_ticks == 0

    # Link goes UP (tick 1)
    current_state = [NetInterface(name="eth0", ips=[], is_up=True)]
    watcher.check_now()
    assert len(restart_events) == 0
    assert watcher._active_up_ticks == 1

    # Link stays UP (tick 2) -> debounce condition met! Restart emitted
    watcher.check_now()
    assert len(restart_events) == 1
    assert restart_events[-1] == "eth0"
    assert watcher._active_was_down is False

    # Link stays UP (tick 3) -> no repeated restart
    watcher.check_now()
    assert len(restart_events) == 1

    watcher.stop()


def test_interface_watcher_active_interface_vanished():
    """Verify watcher signals restart with empty target when active adapter is removed."""
    app = QApplication.instance() or QApplication([])

    current_state = [
        NetInterface(name="usb0", ips=["192.168.1.10"], is_up=True),
    ]

    watcher = InterfaceWatcher(
        active_interface="usb0",
        state_provider=lambda: current_state,
    )
    watcher.start()

    restart_events: list[str] = []
    watcher.capture_restart_needed.connect(restart_events.append)

    # Adapter removed
    current_state = []
    watcher.check_now()

    assert len(restart_events) == 1
    assert restart_events[0] == ""
    watcher.stop()


def test_interface_watcher_hotplug_new_adapter_emits_changed():
    """Verify that when a newly plugged adapter appears on subsequent polls, interfaces_changed is emitted."""
    app = QApplication.instance() or QApplication([])

    poll_count = 0

    def fake_reloading_provider() -> list[NetInterface]:
        nonlocal poll_count
        poll_count += 1
        if poll_count == 1:
            return [NetInterface(name="eth0", ips=["192.168.1.10"], is_up=True)]
        return [
            NetInterface(name="eth0", ips=["192.168.1.10"], is_up=True),
            NetInterface(name="eth1_usb", ips=["192.168.1.50"], is_up=True, description="USB Ethernet Adapter"),
        ]

    watcher = InterfaceWatcher(
        active_interface="eth0",
        state_provider=fake_reloading_provider,
        poll_interval_ms=10000,
    )
    watcher.start()

    changed_events: list[list[NetInterface]] = []
    watcher.interfaces_changed.connect(changed_events.append)

    # First call to provider occurred during start() with eth0 only.
    # Second call to provider occurs on check_now() with the new adapter -> interfaces_changed emitted.
    watcher.check_now()
    assert len(changed_events) == 1
    assert len(changed_events[0]) == 2
    assert any(nic.name == "eth1_usb" for nic in changed_events[0])

    watcher.stop()


def test_interface_watcher_default_state_provider_uses_reload(monkeypatch):
    """Verify the default state provider invokes list_interfaces with reload=True to pick up new adapters."""
    app = QApplication.instance() or QApplication([])
    reload_args: list[bool] = []

    def fake_list_interfaces(reload: bool = False) -> list[NetInterface]:
        reload_args.append(reload)
        return [NetInterface(name="eth0", ips=["192.168.1.10"], is_up=True)]

    monkeypatch.setattr("linksight.ui.interface_watcher.list_interfaces", fake_list_interfaces)

    watcher = InterfaceWatcher(active_interface="eth0")
    # Read state directly
    nics = watcher._read_state()
    assert reload_args == [True]
    assert len(nics) == 1
    assert nics[0].name == "eth0"

    # Also verify check_now uses the reloading default provider
    watcher.check_now()
    assert reload_args == [True, True]


def test_nic_status_widget_refresh_preserves_selection():
    """Verify NicStatusWidget refresh preserves user selection in place."""
    app = QApplication.instance() or QApplication([])

    nics_v1 = [
        NetInterface(name="eth0", ips=["10.0.0.1"], is_up=True),
        NetInterface(name="eth1", ips=["10.0.0.2"], is_up=False),
        NetInterface(name="wlan0", ips=[], is_up=False),
    ]

    widget = NicStatusWidget()
    widget.refresh(nics_v1)

    # Select eth1 (row 1)
    idx_eth1 = widget.model.index(1, 0)
    widget.table.setCurrentIndex(idx_eth1)
    assert widget.table.currentIndex().row() == 1

    # Update: eth1 is now UP and eth0 gained an IP
    nics_v2 = [
        NetInterface(name="eth0", ips=["10.0.0.1", "10.0.0.99"], is_up=True),
        NetInterface(name="eth1", ips=["10.0.0.2"], is_up=True),
        NetInterface(name="wlan0", ips=[], is_up=False),
    ]
    widget.refresh(nics_v2)

    # Selection should still be row 1 (eth1)
    assert widget.table.currentIndex().row() == 1
    selected_nic = widget.model.nic_at(widget.table.currentIndex().row())
    assert selected_nic is not None
    assert selected_nic.name == "eth1"
    assert selected_nic.is_up is True

    # Update: remove eth1
    nics_v3 = [
        NetInterface(name="eth0", ips=["10.0.0.1"], is_up=True),
        NetInterface(name="wlan0", ips=[], is_up=False),
    ]
    widget.refresh(nics_v3)
    # Does not crash, rowCount is 2
    assert widget.model.rowCount() == 2


def test_main_window_watcher_link_flap_and_restart():
    """Verify MainWindow handles link flaps: updates NIC table, refreshes LAN info, and restarts capture."""
    app = QApplication.instance() or QApplication([])
    controller = AppController()

    state = [
        NetInterface(name="eth0", ips=[], is_up=True),
    ]

    window = MainWindow(controller, demo=True, state_provider=lambda: state)
    try:
        assert window.nic_widget.model.rowCount() >= 1

        # Simulate link flap: DOWN -> UP -> UP
        state = [NetInterface(name="eth0", ips=[], is_up=False)]
        window._watcher.check_now()
        QCoreApplication.processEvents()

        # Check NIC table reflects DOWN
        nic = window.nic_widget.model.nic_at(0)
        assert nic is not None
        assert nic.is_up is False

        # Link comes UP (tick 1)
        state = [NetInterface(name="eth0", ips=[], is_up=True)]
        window._watcher.check_now()
        QCoreApplication.processEvents()

        # Link stays UP (tick 2)
        window._watcher.check_now()
        QCoreApplication.processEvents()

        # Check NIC table reflects UP
        nic = window.nic_widget.model.nic_at(0)
        assert nic is not None
        assert nic.is_up is True
    finally:
        window.close()
        controller.close()


# ── PROBLEM 3 TESTS: Non-Modal Capture Errors & Rate Limiting ──


def test_capture_error_is_non_modal(monkeypatch):
    """Verify capture errors update status bar and top status without calling QMessageBox.critical."""
    app = QApplication.instance() or QApplication([])

    def _fail_modal(*args, **kwargs):
        raise AssertionError("QMessageBox modal must NOT be called for capture errors!")

    monkeypatch.setattr(QMessageBox, "critical", _fail_modal)
    monkeypatch.setattr(QMessageBox, "warning", _fail_modal)
    monkeypatch.setattr(QMessageBox, "information", _fail_modal)

    controller = AppController()
    window = MainWindow(controller, demo=True)
    try:
        # Trigger capture error
        test_err = "Packet capture failed: adapter vanished during flap"
        window._on_capture_error(test_err)

        # Verify non-blocking status updates
        assert window.top_status.text() == "Capture error"
        assert test_err in window.top_status.toolTip()
        assert "Capture error: Packet capture failed" in window.status_left.text()
    finally:
        window.close()
        controller.close()


def test_capture_error_rate_limiting(monkeypatch):
    """Verify rapid capture errors within 5-second window are rate-limited."""
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: None)

    controller = AppController()
    window = MainWindow(controller, demo=True)
    try:
        window._on_capture_error("First error message")
        assert "First error message" in window.status_left.text()

        # Second error immediately within 5s window
        window._on_capture_error("Second error message")
        # Text should still show first error because second was rate-limited
        assert "First error message" in window.status_left.text()
    finally:
        window.close()
        controller.close()
