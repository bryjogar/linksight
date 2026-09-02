import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication
from linksight.parse.model import NeighborDevice
from linksight.ui.controller import AppController
from linksight.ui.lan_info_widget import InterfaceConfigWorker
from linksight.ui.main_window import MainWindow, ArpResolveWorker, UpstreamWorker


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


def test_arp_resolve_worker_cancellation():
    """Verify ArpResolveWorker exits cleanly when stopped without emitting a bogus result."""
    app = QApplication.instance() or QApplication([])
    started = threading.Event()
    unblock = threading.Event()

    def slow_resolver(dev, stop_check=None):
        started.set()
        while not unblock.is_set():
            if stop_check and stop_check():
                return None
            time.sleep(0.01)
        return "192.168.1.99"

    dev = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        system_name="Test-SW",
        chassis_id="00:11:22:33:44:55",
        management_ips=[],
    )
    worker = ArpResolveWorker(dev, resolver=slow_resolver)
    emitted_finished = []
    emitted_cancelled = []
    worker.finished.connect(emitted_finished.append)
    worker.cancelled.connect(lambda: emitted_cancelled.append(True))

    worker.start()
    assert started.wait(timeout=2.0) is True
    assert worker.isRunning() is True

    # Stop the worker
    worker.stop()
    unblock.set()
    assert worker.wait(1000) is True
    assert worker.isRunning() is False
    QCoreApplication.processEvents()
    assert emitted_finished == []  # No bogus result emitted
    assert len(emitted_cancelled) == 1


def test_upstream_worker_cancellation():
    """Verify UpstreamWorker exits cleanly when stopped without emitting a finished path."""
    app = QApplication.instance() or QApplication([])
    worker = UpstreamWorker("10.0.0.3", "public", is_demo=True)
    emitted_finished = []
    emitted_cancelled = []
    worker.finished.connect(emitted_finished.append)
    worker.cancelled.connect(lambda: emitted_cancelled.append(True))

    worker.start()
    time.sleep(0.05)
    assert worker.isRunning() is True

    worker.stop()
    assert worker.wait(1500) is True
    assert worker.isRunning() is False
    QCoreApplication.processEvents()
    assert emitted_finished == []
    assert len(emitted_cancelled) == 1


def test_interface_config_worker_cancellation():
    """Verify InterfaceConfigWorker exits cleanly when stopped before or during run."""
    app = QApplication.instance() or QApplication([])
    worker = InterfaceConfigWorker("lo")
    emitted_finished = []
    emitted_cancelled = []
    worker.finished.connect(emitted_finished.append)
    worker.cancelled.connect(lambda: emitted_cancelled.append(True))

    worker.stop()
    worker.start()
    assert worker.wait(1000) is True
    assert worker.isRunning() is False
    QCoreApplication.processEvents()
    assert emitted_finished == []
    assert len(emitted_cancelled) == 1


def test_start_arp_resolve_queues_rather_than_terminates(monkeypatch):
    """Verify _start_arp_resolve queues new request rather than calling terminate on busy worker."""
    from linksight.ui import main_window as mw_mod
    monkeypatch.setattr(mw_mod.MainWindow, "_on_capture_error", lambda self, msg: None)

    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=False)

    started_first = threading.Event()
    unblock_first = threading.Event()

    calls = []

    def mock_resolver(dev, stop_check=None):
        calls.append(dev.system_name)
        if dev.system_name == "SW-1":
            started_first.set()
            while not unblock_first.is_set():
                if stop_check and stop_check():
                    return None
                time.sleep(0.01)
            return "192.168.1.11"
        return "192.168.1.22"

    monkeypatch.setattr(
        "linksight.discovery.arp_resolve.resolve_switch_mgmt_ip",
        mock_resolver,
    )

    dev1 = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        system_name="SW-1",
        chassis_id="00:11:22:33:44:01",
        management_ips=[],
    )
    dev2 = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        system_name="SW-2",
        chassis_id="00:11:22:33:44:02",
        management_ips=[],
    )

    try:
        # Start first device
        window._start_arp_resolve(dev1)
        assert started_first.wait(timeout=2.0) is True
        assert window._arp_worker is not None
        assert window._arp_worker.isRunning() is True
        first_worker = window._arp_worker

        # Start second device while first is busy
        window._start_arp_resolve(dev2)

        # First worker was NOT terminated — it was stopped cooperatively and dev2 was queued
        assert window._pending_arp_dev == dev2
        assert first_worker.is_stopped is True

        # Release first worker
        unblock_first.set()
        first_worker.wait(2000)
        QCoreApplication.processEvents()

        # Verify second worker was started for dev2
        assert window._arp_worker is not None
        window._arp_worker.wait(2000)
        QCoreApplication.processEvents()

        assert window.switch_widget._current_mgmt_ip == "192.168.1.22"
        assert "SW-1" in calls
        assert "SW-2" in calls
    finally:
        window.close()
        controller.close()


def test_main_window_ambiguous_continue_wiring():
    """Verify _on_upstream_continue runs continuation walk with forced_next_ip in demo mode."""
    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=True)

    try:
        # Simulate ambiguous hop start at 192.168.1.20
        window._current_walk_ip = "192.168.1.20"
        window._on_upstream_continue("10.0.0.10")

        assert window._upstream_worker is not None
        assert window._upstream_worker.forced_next_ip == "10.0.0.10"
        window._upstream_worker.wait(3000)
        QCoreApplication.processEvents()

        assert "Aruba-2930F" in window.upstream_widget.summary_label.text()
        assert len(window.controller.upstream_path.hops) == 2
        assert window.controller.upstream_path.hops[0].uplink_port.neighbor_ip == "10.0.0.10"
    finally:
        window.close()
        controller.close()


def test_main_window_no_ip_candidate_arp_resolve_success(monkeypatch):
    """Verify that clicking a candidate with no management IP triggers ARP resolution,
    and when ARP succeeds, discovery continues with the resolved IP as forced_next_ip.
    """
    from linksight.discovery.models import PortDiagnostics
    import linksight.ui.main_window as mw_mod

    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=False)

    cand = PortDiagnostics(
        port_id=47,
        port_name="Port 47",
        neighbor_name="UniFi-Switch",
        neighbor_ip="",
        neighbor_chassis="74:83:c2:11:22:33",
    )

    resolved_calls = []

    def mock_resolve(dev):
        resolved_calls.append(dev)
        return "192.168.1.88"

    monkeypatch.setattr(mw_mod, "resolve_switch_mgmt_ip", mock_resolve)
    monkeypatch.setattr(mw_mod.UpstreamWorker, "start", lambda self: None)
    window._session_community = "public"

    try:
        window._current_walk_ip = "10.0.0.10"
        window._on_upstream_continue({
            "candidate": cand,
            "hop_mgmt_ip": "10.0.0.10",
            "port_id": 47,
        })

        assert len(resolved_calls) == 1
        assert resolved_calls[0].chassis_id == "74:83:c2:11:22:33"
        assert resolved_calls[0].management_ips == []
        assert window._upstream_worker is not None
        assert window._upstream_worker.start_ip == "10.0.0.10"
        assert window._upstream_worker.forced_next_ip == "192.168.1.88"
        assert window._upstream_worker.forced_port_id == 47
        assert window._upstream_worker.forced_hop_ip == "10.0.0.10"
        assert window._upstream_worker.forced_candidate == cand
    finally:
        window.close()
        controller.close()


def test_main_window_no_ip_candidate_arp_fails_manual_prompt(monkeypatch):
    """Verify that clicking a candidate with no management IP triggers ARP resolution,
    and when ARP fails, falls back to manual QInputDialog entry and continues with entered IP.
    """
    from PySide6.QtWidgets import QInputDialog
    from linksight.discovery.models import PortDiagnostics
    import linksight.ui.main_window as mw_mod

    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=False)

    cand = PortDiagnostics(
        port_id=47,
        port_name="Port 47",
        neighbor_name="UniFi-Switch",
        neighbor_ip="",
        neighbor_chassis="74:83:c2:11:22:33",
    )

    # ARP resolve returns None
    monkeypatch.setattr(mw_mod, "resolve_switch_mgmt_ip", lambda dev: None)

    # Mock QInputDialog.getText to return a user-entered IP
    prompt_shown = []

    def mock_get_text(parent, title, label, echo=None):
        prompt_shown.append((title, label))
        return "192.168.1.99", True

    monkeypatch.setattr(QInputDialog, "getText", mock_get_text)

    requested_calls = []
    monkeypatch.setattr(window, "_on_upstream_requested", lambda start_ip, forced_next_ip=None, **kw: requested_calls.append((start_ip, forced_next_ip)))

    try:
        window._current_walk_ip = "10.0.0.10"
        window._on_upstream_continue(cand)

        assert len(prompt_shown) == 1
        assert "UniFi-Switch" in prompt_shown[0][1]
        assert len(requested_calls) == 1
        assert requested_calls[0] == ("10.0.0.10", "192.168.1.99")
    finally:
        window.close()
        controller.close()


def test_main_window_no_ip_candidate_demo_mode():
    """Verify that in demo mode, clicking a candidate with no IP uses canned resolution
    (192.168.1.20) and continues the walk offscreen.
    """
    from linksight.discovery.models import PortDiagnostics

    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=True)

    cand = PortDiagnostics(
        port_id=47,
        port_name="Port 47",
        neighbor_name="UniFi-Switch",
        neighbor_ip="",
        neighbor_chassis="74:83:c2:11:22:33",
    )

    try:
        window._current_walk_ip = "10.0.0.10"
        window._on_upstream_continue(cand)

        assert window._upstream_worker is not None
        assert window._upstream_worker.forced_next_ip == "192.168.1.20"
        assert window._upstream_worker.forced_port_id == 47
        assert window._upstream_worker.forced_hop_ip == "10.0.0.10"
        window._upstream_worker.wait(3000)
        QCoreApplication.processEvents()

        assert len(window.controller.upstream_path.hops) == 3
        assert window.controller.upstream_path.hops[0].uplink_port.neighbor_ip == "192.168.1.20"
        assert window.controller.upstream_path.hops[1].hostname == "UniFi-Switch"
        assert window.controller.upstream_path.hops[2].hostname == "Eero-Mesh"
    finally:
        window.close()
        controller.close()


def test_main_window_candidate_button_click_continues_demo():
    """Verify that clicking the candidate button in the UI in demo mode initiates
    continuation carrying port 47 and successfully reaches UniFi-Switch.
    """
    from linksight.discovery.demo import get_aruba_demo_path
    from PySide6.QtWidgets import QPushButton

    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=True)

    try:
        path = get_aruba_demo_path()
        window._current_walk_ip = "10.0.0.10"
        window.upstream_widget.show_path(path)

        cand_btn_47 = window.upstream_widget.findChild(QPushButton, "candidate_btn_47")
        assert cand_btn_47 is not None
        assert "▶ Try UniFi-Switch (on Port 47)" in cand_btn_47.text()

        cand_btn_47.click()

        assert window._upstream_worker is not None
        assert window._upstream_worker.forced_next_ip == "192.168.1.20"
        assert window._upstream_worker.forced_port_id == 47
        assert window._upstream_worker.forced_hop_ip == "10.0.0.10"

        window._upstream_worker.wait(3000)
        QCoreApplication.processEvents()

        assert len(window.controller.upstream_path.hops) == 3
        assert window.controller.upstream_path.hops[0].uplink_port.port_id == 47
        assert window.controller.upstream_path.hops[0].uplink_port.neighbor_ip == "192.168.1.20"
        assert window.controller.upstream_path.hops[1].hostname == "UniFi-Switch"
        assert window.controller.upstream_path.hops[2].hostname == "Eero-Mesh"
    finally:
        window.close()
        controller.close()
