"""Offscreen UI tests for Upstream Discovery widgets and flow."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QCoreApplication

from linksight.discovery.demo import get_demo_path
from linksight.parse.model import NeighborDevice
from linksight.ui.controller import AppController
from linksight.ui.main_window import MainWindow
from linksight.ui.switch_info_widget import SwitchInfoWidget
from linksight.ui.upstream_widget import UpstreamWidget, HopCardWidget


def test_upstream_widget_render_demo_path():
    """Verify UpstreamWidget correctly renders the multi-hop demo chain with path summary, WAN handoff, and collapsed table."""
    from PySide6.QtWidgets import QFrame, QLabel

    app = QApplication.instance() or QApplication([])

    widget = UpstreamWidget()
    widget.show()
    path = get_demo_path("10.0.0.3")

    widget.show_path(path)

    assert widget.summary_label.text() != ""
    assert "FW-Edge01" in widget.summary_label.text()
    assert "203.0.113.1" in widget.summary_label.text()
    assert "wan1" in widget.summary_label.text()
    assert not widget.breadcrumb_bar.isHidden()
    assert "Access-SW2" in widget.breadcrumb_bar.text()
    assert "Core-SW1" in widget.breadcrumb_bar.text()
    assert "203.0.113.1" in widget.breadcrumb_bar.text()

    # Verify cards in layout
    card_count = 0
    cards: list[HopCardWidget] = []
    for i in range(widget.cards_layout.count()):
        item = widget.cards_layout.itemAt(i)
        w = item.widget()
        if isinstance(w, HopCardWidget):
            card_count += 1
            cards.append(w)
            assert w.hop is not None
            assert w.expanded is True
            # Test whole-card toggle
            w._toggle_expand()
            assert w.expanded is False
            assert w.body.isHidden() is True
            w._toggle_expand()
            assert w.expanded is True
            assert not w.body.isHidden()

    assert card_count == 3

    # 1. Hop 1 (Access-SW2): Path summary block with downlink Gi1/0/1 and uplink Gi1/0/24
    hop1_card = cards[0]
    hop1_summary = hop1_card.findChild(QFrame, "path_summary")
    assert hop1_summary is not None
    hop1_labels_text = " ".join(lbl.text() for lbl in hop1_summary.findChildren(QLabel))
    assert "Gi1/0/1" in hop1_labels_text
    assert "Gi1/0/24" in hop1_labels_text
    # Table collapsed by default
    assert hop1_card.table is not None
    assert hop1_card.table.isHidden() is True
    assert hop1_card.ports_toggle_btn is not None
    assert "All 4 ports" in hop1_card.ports_toggle_btn.text()
    # Click toggle -> expands
    hop1_card.ports_toggle_btn.click()
    assert hop1_card.table.isHidden() is False
    assert "All 4 ports" in hop1_card.ports_toggle_btn.text()
    # Click toggle again -> collapses
    hop1_card.ports_toggle_btn.click()
    assert hop1_card.table.isHidden() is True

    # 2. Hop 2 (Core-SW1): Path summary block with downlink Gi0/24 and uplink Gi0/1
    hop2_card = cards[1]
    hop2_summary = hop2_card.findChild(QFrame, "path_summary")
    assert hop2_summary is not None
    hop2_labels_text = " ".join(lbl.text() for lbl in hop2_summary.findChildren(QLabel))
    assert "Gi0/24" in hop2_labels_text
    assert "Gi0/1" in hop2_labels_text
    # Table collapsed by default
    assert hop2_card.table is not None
    assert hop2_card.table.isHidden() is True
    hop2_card.ports_toggle_btn.click()
    assert hop2_card.table.isHidden() is False
    hop2_card.ports_toggle_btn.click()
    assert hop2_card.table.isHidden() is True

    # 3. Hop 3 (FW-Edge01): WAN handoff block and collapsed table
    fw_card = cards[2]
    assert fw_card.hop.hostname == "FW-Edge01"
    assert fw_card.hop.wan_interface is not None
    assert fw_card.hop.wan_interface.port_name == "wan1"
    assert fw_card.hop.isp_gateway == "203.0.113.1"
    assert fw_card.hop.lan_interface is not None
    assert fw_card.hop.lan_interface.port_name == "lan"
    wan_frame = fw_card.findChild(QFrame, "wan_handoff")
    assert wan_frame is not None
    assert fw_card.table is not None
    assert fw_card.table.isHidden() is True
    fw_card.ports_toggle_btn.click()
    assert fw_card.table.isHidden() is False
    fw_card.ports_toggle_btn.click()
    assert fw_card.table.isHidden() is True

    # Test clear
    widget.clear()
    assert widget.breadcrumb_bar.isVisible() is False


def test_hop_card_widget_wan_handoff():
    """Verify HopCardWidget renders WAN handoff and interface table with mixed statuses."""
    from PySide6.QtWidgets import QFrame
    from linksight.discovery.models import Hop, PortDiagnostics

    app = QApplication.instance() or QApplication([])

    wan_port = PortDiagnostics(
        port_id=1,
        port_name="wan1",
        link_speed_mbps=1000,
        oper_status="up",
        is_uplink=True,
    )
    lan_port = PortDiagnostics(
        port_id=2,
        port_name="lan",
        link_speed_mbps=1000,
        oper_status="up",
        is_downlink=True,
    )
    dmz_port = PortDiagnostics(
        port_id=3,
        port_name="dmz",
        link_speed_mbps=100,
        oper_status="down",
    )

    hop = Hop(
        hop_index=1,
        hostname="FW-Core",
        mgmt_ip="192.168.1.1",
        device_type="firewall",
        status="router_reached",
        isp_gateway="198.51.100.1",
        wan_interface=wan_port,
        lan_interface=lan_port,
        ports=[wan_port, lan_port, dmz_port],
    )

    card = HopCardWidget(hop)
    card.show()

    wan_frame = card.findChild(QFrame, "wan_handoff")
    assert wan_frame is not None
    card.close()


def test_switch_info_widget_upstream_button():
    """Verify SwitchInfoWidget upstream button enables on device presence and handles missing management IP."""
    app = QApplication.instance() or QApplication([])

    widget = SwitchInfoWidget()
    assert widget.upstream_btn.isEnabled() is False
    assert widget.upstream_btn.toolTip() == "No switch detected"

    # 1. Device WITHOUT management IP (UniFi switch case)
    dev_no_ip = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        system_name="USW-Lite-16-PoE",
        management_ips=[],
        port_id="Port 1",
    )
    widget.show_device(dev_no_ip)
    assert widget.upstream_btn.isEnabled() is True
    assert widget._current_mgmt_ip == ""
    assert widget.upstream_btn.toolTip() == (
        "No management IP advertised by switch — click to enter the switch management IP"
    )

    # Clicking button with no IP emits empty string
    emitted_ips = []
    widget.upstream_requested.connect(emitted_ips.append)
    widget.upstream_btn.click()
    assert emitted_ips == [""]

    # 2. Clear disables button
    widget.clear()
    assert widget.upstream_btn.isEnabled() is False
    assert widget._current_mgmt_ip == ""
    assert widget.upstream_btn.toolTip() == "No switch detected"

    # 3. Device WITH management IP
    dev_with_ip = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        system_name="Core-SW1",
        management_ips=["10.0.0.2"],
        port_id="Gi0/24",
    )
    widget.show_device(dev_with_ip)
    assert widget.upstream_btn.isEnabled() is True
    assert widget._current_mgmt_ip == "10.0.0.2"
    assert widget.upstream_btn.toolTip() == "Walk upstream switches starting from 10.0.0.2"

    emitted_ips.clear()
    widget.upstream_btn.click()
    assert emitted_ips == ["10.0.0.2"]

    # 4. Setting management IP manually updates widget state
    widget.set_management_ip("192.168.1.50")
    assert widget._current_mgmt_ip == "192.168.1.50"
    assert widget.upstream_btn.toolTip() == "Walk upstream switches starting from 192.168.1.50"
    emitted_ips.clear()
    widget.upstream_btn.click()
    assert emitted_ips == ["192.168.1.50"]


def test_main_window_demo_upstream_discovery():
    """Verify MainWindow executes upstream discovery in demo mode without errors."""
    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=True)

    try:
        # Trigger upstream discovery
        window._on_upstream_requested("10.0.0.3")
        assert window._upstream_worker is not None

        # Wait for worker thread to complete
        window._upstream_worker.wait(5000)
        QCoreApplication.processEvents()

        # Verify upstream widget received the path
        assert window.upstream_widget.summary_label.text() != ""
        assert len(window.controller.upstream_path.hops) == 3
    finally:
        window.close()
        controller.close()


def test_main_window_demo_upstream_discovery_empty_ip():
    """Verify MainWindow in demo mode starts walk falling back to 10.0.0.3 when start_ip is empty."""
    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=True)

    try:
        # Trigger upstream discovery with empty start_ip (e.g. from UniFi button click)
        window._on_upstream_requested("")
        assert window._upstream_worker is not None
        assert window._upstream_worker.start_ip == "10.0.0.3"
        assert window.switch_widget._current_mgmt_ip == "10.0.0.3"
        assert "10.0.0.3" in window.upstream_widget.summary_label.text()

        # Wait for worker thread to complete
        window._upstream_worker.wait(5000)
        QCoreApplication.processEvents()

        # Verify upstream widget received the path
        assert window.upstream_widget.summary_label.text() != ""
        assert len(window.controller.upstream_path.hops) == 3
    finally:
        window.close()
        controller.close()


def test_main_window_real_upstream_discovery_prompt(monkeypatch):
    """Verify MainWindow in real mode prompts for switch IP when empty, and validates IPv4."""
    from PySide6.QtWidgets import QInputDialog
    from linksight.ui.main_window import UpstreamWorker

    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=False)

    try:
        # 1. User cancels IP dialog -> nothing happens
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("", False))
        window._on_upstream_requested("")
        assert window._upstream_worker is None

        # Prevent worker thread from running actual SNMP network calls
        monkeypatch.setattr(UpstreamWorker, "start", lambda self: None)

        # 2. User enters invalid IP, then valid IP, then SNMP community
        dialog_responses = [
            ("bad-ip", True),
            ("192.168.1.10", True),
            ("public", True),
        ]
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: dialog_responses.pop(0))

        window._on_upstream_requested("")
        assert window.switch_widget._current_mgmt_ip == "192.168.1.10"
        assert window._current_walk_ip == "192.168.1.10"
        assert window._upstream_worker is not None
        assert window._upstream_worker.start_ip == "192.168.1.10"
        assert window._upstream_worker.community == "public"
    finally:
        window.close()
        controller.close()


def test_hop_card_widget_path_summary_modes():
    """Verify HopCardWidget gracefully renders only-uplink, only-downlink, and dual-port summaries."""
    from PySide6.QtWidgets import QFrame, QLabel
    from linksight.discovery.models import Hop, PortDiagnostics

    app = QApplication.instance() or QApplication([])

    up_port = PortDiagnostics(
        port_id=24,
        port_name="Gi1/0/24",
        pvid=100,
        link_speed_mbps=1000,
        stp_state="forwarding",
        is_uplink=True,
        neighbor_name="Core-SW1",
        neighbor_ip="10.0.0.2",
    )

    down_port = PortDiagnostics(
        port_id=1,
        port_name="Gi1/0/1",
        pvid=200,
        link_speed_mbps=1000,
        stp_state="forwarding",
        is_downlink=True,
        neighbor_name="Host-PC",
    )

    # Mode 1: Only Uplink (no downlink identified)
    hop_up_only = Hop(
        hop_index=1,
        hostname="Switch-A",
        mgmt_ip="10.0.0.10",
        uplink_port=up_port,
        ports=[up_port],
    )
    card1 = HopCardWidget(hop_up_only)
    card1.show()
    summary1 = card1.findChild(QFrame, "path_summary")
    assert summary1 is not None
    text1 = " ".join(lbl.text() for lbl in summary1.findChildren(QLabel))
    assert "Gi1/0/24" in text1
    assert "Core-SW1" in text1
    assert "DOWNLINK" not in text1  # No dead space / noise rows
    assert card1.table is not None
    assert card1.table.isHidden() is True
    card1.close()

    # Mode 2: Only Downlink (STP Root bridge with no upstream uplink)
    hop_down_only = Hop(
        hop_index=2,
        hostname="Switch-Root",
        mgmt_ip="10.0.0.2",
        is_stp_root=True,
        downlink_port=down_port,
        ports=[down_port],
    )
    card2 = HopCardWidget(hop_down_only)
    card2.show()
    summary2 = card2.findChild(QFrame, "path_summary")
    assert summary2 is not None
    text2 = " ".join(lbl.text() for lbl in summary2.findChildren(QLabel))
    assert "Gi1/0/1" in text2
    assert "Host-PC" in text2
    assert "ROOT / UPLINK" not in text2  # No empty uplink block
    card2.close()

