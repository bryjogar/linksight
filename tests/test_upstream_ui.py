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
    """Verify UpstreamWidget correctly renders the multi-hop demo chain with WAN handoff."""
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
            # Test toggle
            w._toggle_expand()
            assert w.expanded is False
            assert w.body.isHidden() is True
            w._toggle_expand()
            assert w.expanded is True
            assert not w.body.isHidden()

    assert card_count == 3
    # Verify FW-Edge01 card has WAN handoff block
    fw_card = cards[2]
    assert fw_card.hop.hostname == "FW-Edge01"
    assert fw_card.hop.wan_interface is not None
    assert fw_card.hop.wan_interface.port_name == "wan1"
    assert fw_card.hop.isp_gateway == "203.0.113.1"
    assert fw_card.hop.lan_interface is not None
    assert fw_card.hop.lan_interface.port_name == "lan"

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
    """Verify SwitchInfoWidget upstream button enables/disables and emits signal."""
    app = QApplication.instance() or QApplication([])

    widget = SwitchInfoWidget()
    assert widget.upstream_btn.isEnabled() is False

    # Show a device with management IP
    dev = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        system_name="Core-SW1",
        management_ips=["10.0.0.2"],
        port_id="Gi0/24",
    )
    widget.show_device(dev)
    assert widget.upstream_btn.isEnabled() is True
    assert widget._current_mgmt_ip == "10.0.0.2"

    # Test clicking emits signal
    emitted_ips = []
    widget.upstream_requested.connect(emitted_ips.append)
    widget.upstream_btn.click()
    assert emitted_ips == ["10.0.0.2"]

    # Clear disables button
    widget.clear()
    assert widget.upstream_btn.isEnabled() is False
    assert widget._current_mgmt_ip == ""


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
