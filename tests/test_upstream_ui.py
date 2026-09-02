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

    # 1. Hop 1 (Access-SW2): Path summary block with downlink Port 3 and uplink Gi1/0/24
    hop1_card = cards[0]
    hop1_summary = hop1_card.findChild(QFrame, "path_summary")
    assert hop1_summary is not None
    hop1_labels_text = " ".join(lbl.text() for lbl in hop1_summary.findChildren(QLabel))
    assert "Port 3" in hop1_labels_text
    assert "Gi1/0/24" in hop1_labels_text
    # Item 3: Current-port VLAN/STP/speed details outside the collapsed table
    assert "PVID 1" in hop1_labels_text
    assert "UNTAGGED 1" in hop1_labels_text
    assert "TAGGED 30" in hop1_labels_text
    assert "STP forwarding" in hop1_labels_text
    assert "1 Gbps" in hop1_labels_text
    assert "PVID 100" in hop1_labels_text
    assert "UNTAGGED 100" in hop1_labels_text
    assert "TAGGED 200, 300" in hop1_labels_text
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

    # 5. Setting auto-resolved management IP updates widget state with (ARP) marker
    from PySide6.QtWidgets import QLabel
    widget.set_resolved_mgmt_ip("192.168.1.20")
    assert widget._current_mgmt_ip == "192.168.1.20"
    assert widget.upstream_btn.toolTip() == (
        "Walk upstream switches starting from 192.168.1.20 (auto-resolved via ARP)"
    )
    emitted_ips.clear()
    widget.upstream_btn.click()
    assert emitted_ips == ["192.168.1.20"]
    mgmt_widget = widget.grid.itemAtPosition(widget._mgmt_ip_row_idx, 1).widget()
    labels = [lbl.text() for lbl in mgmt_widget.findChildren(QLabel)]
    assert any("(ARP)" in t for t in labels)
    assert any("192.168.1.20" in t for t in labels)


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


def test_main_window_arp_resolve_success(monkeypatch):
    """UI test: show_device with no mgmt IP + mocked resolve result -> _current_mgmt_ip set and tooltip updated."""
    # demo=False auto-starts a real sniffer; in the headless test env it errors
    # and would raise a MODAL capture-error dialog that blocks processEvents
    # forever. Stub the handler — the capture pipeline is not under test here.
    from linksight.ui import main_window as mw_mod
    monkeypatch.setattr(mw_mod.MainWindow, "_on_capture_error", lambda self, msg: None)

    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=False)

    try:
        monkeypatch.setattr(
            "linksight.discovery.arp_resolve.resolve_switch_mgmt_ip",
            lambda dev: "192.168.1.20",
        )

        dev = NeighborDevice(
            protocol="lldp",
            source_interface="eth0",
            system_name="USW-Lite-16-PoE",
            chassis_id="74:83:c2:11:22:33",
            management_ips=[],
            port_id="Port 1",
        )

        window._on_device(dev)

        assert window._arp_worker is not None
        window._arp_worker.wait(5000)
        QCoreApplication.processEvents()

        assert window.switch_widget._current_mgmt_ip == "192.168.1.20"
        assert window.switch_widget.upstream_btn.isEnabled() is True
        assert window.switch_widget.upstream_btn.toolTip() == (
            "Walk upstream switches starting from 192.168.1.20 (auto-resolved via ARP)"
        )
    finally:
        window.close()
        controller.close()


def test_main_window_arp_resolve_none(monkeypatch):
    """UI test: show_device with no mgmt IP + mocked resolve None -> button enabled, still prompts on click (existing behavior, regression-guarded)."""
    from PySide6.QtWidgets import QInputDialog
    from linksight.ui import main_window as mw_mod
    from linksight.ui.main_window import UpstreamWorker

    # demo=False auto-starts a real sniffer; headless env errors would raise a
    # MODAL capture-error dialog that blocks processEvents forever.
    monkeypatch.setattr(mw_mod.MainWindow, "_on_capture_error", lambda self, msg: None)

    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=False)

    try:
        monkeypatch.setattr(
            "linksight.discovery.arp_resolve.resolve_switch_mgmt_ip",
            lambda dev: None,
        )

        dev = NeighborDevice(
            protocol="lldp",
            source_interface="eth0",
            system_name="USW-Lite-16-PoE",
            chassis_id="74:83:c2:11:22:33",
            management_ips=[],
            port_id="Port 1",
        )

        window._on_device(dev)

        assert window._arp_worker is not None
        window._arp_worker.wait(5000)
        QCoreApplication.processEvents()

        # Resolution failed: button enabled, empty IP, fallback tooltip
        assert window.switch_widget._current_mgmt_ip == ""
        assert window.switch_widget.upstream_btn.isEnabled() is True
        assert window.switch_widget.upstream_btn.toolTip() == (
            "No management IP advertised by switch — click to enter the switch management IP"
        )

        # Clicking button prompts for manual IP
        monkeypatch.setattr(UpstreamWorker, "start", lambda self: None)
        dialog_responses = [
            ("192.168.1.77", True),
            ("public", True),
        ]
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: dialog_responses.pop(0))

        window.switch_widget.upstream_btn.click()
        assert window.switch_widget._current_mgmt_ip == "192.168.1.77"
        assert window._current_walk_ip == "192.168.1.77"
    finally:
        window.close()
        controller.close()


def test_main_window_demo_arp_auto_resolve():
    """Verify MainWindow in demo mode auto-resolves switches without mgmt IP to canned IP without network I/O."""
    app = QApplication.instance() or QApplication([])
    controller = AppController()
    window = MainWindow(controller, demo=True)

    try:
        dev = NeighborDevice(
            protocol="lldp",
            source_interface="eth0",
            system_name="USW-Lite-16-PoE",
            chassis_id="74:83:c2:11:22:33",
            management_ips=[],
            port_id="Port 1",
        )

        window._on_device(dev)
        assert window._arp_worker is not None
        window._arp_worker.wait(5000)
        QCoreApplication.processEvents()

        assert window.switch_widget._current_mgmt_ip == "192.168.1.20"
        assert "(auto-resolved via ARP)" in window.switch_widget.upstream_btn.toolTip()
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


def test_upstream_widget_render_no_upstream_and_ambiguous():
    """Verify UpstreamWidget renders no_upstream (network edge) and ambiguous edge types gracefully."""
    from PySide6.QtWidgets import QLabel
    from linksight.discovery.models import Hop, PortDiagnostics, UpstreamPath

    app = QApplication.instance() or QApplication([])

    widget = UpstreamWidget()
    widget.show()

    # 1. no_upstream: successful edge stop with NETWORK EDGE badge
    down_port = PortDiagnostics(
        port_id=1,
        port_name="Port 1",
        link_speed_mbps=1000,
        is_downlink=True,
        neighbor_name="Local-Host",
    )
    hop_edge = Hop(
        hop_index=1,
        hostname="USW-Lite-16-PoE",
        mgmt_ip="192.168.1.20",
        status="no_upstream",
        is_stp_root=False,
        downlink_port=down_port,
        ports=[down_port],
    )
    path_no_up = UpstreamPath(
        start_ip="192.168.1.20",
        hops=[hop_edge],
        edge_type="no_upstream",
        edge_summary="No upstream neighbor visible from USW-Lite-16-PoE (192.168.1.20) via LLDP — this switch appears to be the network edge.",
        success=True,
    )
    widget.show_path(path_no_up)

    label_texts = [lbl.text() for lbl in widget.findChildren(QLabel)]
    assert any("NETWORK EDGE" in t for t in label_texts)
    assert "No upstream neighbor visible from USW-Lite-16-PoE" in widget.summary_label.text()
    assert "USW-Lite-16-PoE" in widget.breadcrumb_bar.text()
    # Ensure neither TIMEOUT nor UNREACHABLE is present
    assert not any("TIMEOUT" in t for t in label_texts)
    assert not any("UNREACHABLE" in t for t in label_texts)

    # 2. ambiguous: graceful stop with AMBIGUOUS UPLINK badge and warning summary
    hop_ambig = Hop(
        hop_index=1,
        hostname="USW-Lite-16-PoE",
        mgmt_ip="192.168.1.20",
        status="ambiguous",
        is_stp_root=False,
        downlink_port=down_port,
        ports=[down_port],
    )
    path_ambig = UpstreamPath(
        start_ip="192.168.1.20",
        hops=[hop_ambig],
        edge_type="ambiguous",
        edge_summary="Walk stopped at hop 1 (USW-Lite-16-PoE): multiple upstream LLDP candidate neighbors found (SW-A (10.0.0.10), SW-B (10.0.0.20)) — verify upstream topology.",
        success=False,
    )
    widget.show_path(path_ambig)

    label_texts_ambig = [lbl.text() for lbl in widget.findChildren(QLabel)]
    assert any("AMBIGUOUS UPLINK" in t for t in label_texts_ambig)
    assert "multiple upstream LLDP candidate neighbors" in widget.summary_label.text()
    assert not any("TIMEOUT" in t for t in label_texts_ambig)
    assert not any("UNREACHABLE" in t for t in label_texts_ambig)

    widget.close()


def test_upstream_widget_render_unifi_demo_paths():
    """Verify UpstreamWidget renders canned UniFi demo paths (with upstream and no upstream)."""
    from PySide6.QtWidgets import QLabel
    from linksight.discovery.demo import get_unifi_demo_path

    app = QApplication.instance() or QApplication([])

    widget = UpstreamWidget()
    widget.show()

    # Variant: with_upstream (2 hops: USW -> UDM router edge)
    path_up = get_unifi_demo_path("with_upstream")
    widget.show_path(path_up)
    assert "UDM-Pro" in widget.summary_label.text()
    assert "198.51.100.1" in widget.summary_label.text()
    assert len(path_up.hops) == 2
    lbls = [lbl.text() for lbl in widget.findChildren(QLabel)]
    assert any("ROUTER EDGE" in t for t in lbls)

    # Variant: no_upstream (1 hop: USW network edge)
    path_no_up = get_unifi_demo_path("no_upstream")
    widget.show_path(path_no_up)
    assert "No upstream neighbor visible from USW-Lite-16-PoE" in widget.summary_label.text()
    assert len(path_no_up.hops) == 1
    lbls_no_up = [lbl.text() for lbl in widget.findChildren(QLabel)]
    assert any("NETWORK EDGE" in t for t in lbls_no_up)

    # Variant: ambiguous (1 hop with Aruba and AP candidate buttons)
    path_ambig = get_unifi_demo_path("ambiguous")
    widget.show_path(path_ambig)
    assert "multiple upstream LLDP candidate neighbors" in widget.summary_label.text()
    assert len(path_ambig.hops) == 1
    lbls_ambig = [lbl.text() for lbl in widget.findChildren(QLabel)]
    assert any("AMBIGUOUS UPLINK" in t for t in lbls_ambig)

    # Verify candidate buttons appear in the UI
    from PySide6.QtWidgets import QPushButton
    btns = widget.findChildren(QPushButton)
    btn_texts = [b.text() for b in btns]
    assert any("Aruba-2930F" in t and "10.0.0.10" in t for t in btn_texts)
    assert any("U6-Pro-AP" in t and "192.168.1.50" in t for t in btn_texts)

    widget.close()


def test_hop_card_widget_ambiguous_candidate_buttons():
    """Verify HopCardWidget renders candidate buttons on ambiguous hop and clicking emits continue_from."""
    from PySide6.QtWidgets import QPushButton
    from linksight.discovery.models import Hop, PortDiagnostics, UpstreamPath

    app = QApplication.instance() or QApplication([])

    cand1 = PortDiagnostics(
        port_id=15,
        port_name="Port 15",
        neighbor_name="Aruba-2930F",
        neighbor_ip="10.0.0.10",
        link_speed_mbps=1000,
    )
    cand2 = PortDiagnostics(
        port_id=16,
        port_name="Port 16",
        neighbor_name="U6-Pro-AP",
        neighbor_ip="192.168.1.50",
        link_speed_mbps=1000,
    )
    down_port = PortDiagnostics(
        port_id=1,
        port_name="Port 1",
        is_downlink=True,
        neighbor_name="Host-PC",
    )

    hop = Hop(
        hop_index=1,
        hostname="USW-Lite-16",
        mgmt_ip="192.168.1.20",
        status="ambiguous",
        ports=[down_port, cand1, cand2],
        downlink_port=down_port,
        ambiguous_candidates=[cand1, cand2],
    )

    widget = UpstreamWidget()
    widget.show()
    widget.show_path(UpstreamPath(start_ip="192.168.1.20", hops=[hop], edge_type="ambiguous", success=False))

    emitted: list[str] = []
    widget.continue_from.connect(emitted.append)

    cand_btns = [b for b in widget.findChildren(QPushButton) if "▶ Try" in b.text()]
    assert len(cand_btns) == 2
    assert "▶ Try Aruba-2930F (10.0.0.10) on Port 15" in cand_btns[0].text()
    assert "▶ Try U6-Pro-AP (192.168.1.50) on Port 16" in cand_btns[1].text()

    # Click candidate 1 -> emits structured payload for candidate 1
    cand_btns[0].click()
    assert len(emitted) == 1
    assert emitted[0]["candidate"] == cand1
    assert emitted[0]["hop_mgmt_ip"] == "192.168.1.20"
    assert emitted[0]["port_id"] == 15

    # Click candidate 2 -> emits structured payload for candidate 2
    cand_btns[1].click()
    assert len(emitted) == 2
    assert emitted[1]["candidate"] == cand2
    assert emitted[1]["hop_mgmt_ip"] == "192.168.1.20"
    assert emitted[1]["port_id"] == 16

    widget.close()


def test_upstream_widget_render_aruba_fixture():
    """Verify compact block line shows TAGGED 30 / UNTAGGED 1 for the Aruba fixture."""
    from PySide6.QtWidgets import QFrame, QLabel
    from linksight.discovery.demo import get_aruba_demo_path

    app = QApplication.instance() or QApplication([])
    widget = UpstreamWidget()
    widget.show()
    path = get_aruba_demo_path()

    widget.show_path(path)

    cards: list[HopCardWidget] = [
        widget.cards_layout.itemAt(i).widget()
        for i in range(widget.cards_layout.count())
        if isinstance(widget.cards_layout.itemAt(i).widget(), HopCardWidget)
    ]
    assert len(cards) == 1
    aruba_card = cards[0]
    summary_frame = aruba_card.findChild(QFrame, "path_summary")
    assert summary_frame is not None
    summary_text = " ".join(lbl.text() for lbl in summary_frame.findChildren(QLabel))

    assert "Port 3" in summary_text
    assert "PVID 1" in summary_text
    assert "UNTAGGED 1" in summary_text
    assert "TAGGED 30" in summary_text
    assert "STP forwarding" in summary_text
    assert "1 Gbps" in summary_text

    widget.close()


def test_upstream_widget_render_allowed_vlans_fallback():
    """Verify compact block line keeps 'PVID 1 · VLANs 1,30' format when untagged tables absent."""
    from PySide6.QtWidgets import QFrame, QLabel
    from linksight.discovery.models import Hop, PortDiagnostics, UpstreamPath

    app = QApplication.instance() or QApplication([])
    widget = UpstreamWidget()
    widget.show()

    down_port = PortDiagnostics(
        port_id=1,
        port_name="Gi0/1",
        pvid=1,
        allowed_vlans=[1, 30],
        tagged_vlans=[],
        untagged_vlans=[],
        stp_state="forwarding",
        link_speed_mbps=1000,
        is_downlink=True,
    )
    hop = Hop(
        hop_index=1,
        hostname="Fallback-SW",
        mgmt_ip="10.0.0.5",
        status="ok",
        ports=[down_port],
        downlink_port=down_port,
    )
    path = UpstreamPath(start_ip="10.0.0.5", hops=[hop], success=True)
    widget.show_path(path)

    cards: list[HopCardWidget] = [
        widget.cards_layout.itemAt(i).widget()
        for i in range(widget.cards_layout.count())
        if isinstance(widget.cards_layout.itemAt(i).widget(), HopCardWidget)
    ]
    summary_frame = cards[0].findChild(QFrame, "path_summary")
    summary_text = " ".join(lbl.text() for lbl in summary_frame.findChildren(QLabel))

    assert "PVID 1" in summary_text
    assert "VLANs 1, 30" in summary_text
    assert "UNTAGGED" not in summary_text
    assert "TAGGED" not in summary_text

    widget.close()


def test_upstream_widget_pvid_missing_untagged_fallback():
    """Verify that when pvid is None, effective_pvid falls back to untagged_vlans[0] for display."""
    from PySide6.QtWidgets import QFrame, QLabel
    from linksight.discovery.models import Hop, PortDiagnostics, UpstreamPath

    app = QApplication.instance() or QApplication([])
    widget = UpstreamWidget()
    widget.show()

    down_port = PortDiagnostics(
        port_id=3,
        port_name="Port 3",
        pvid=None,
        allowed_vlans=[1, 30],
        tagged_vlans=[30],
        untagged_vlans=[1],
        stp_state="forwarding",
        link_speed_mbps=1000,
        is_downlink=True,
    )
    hop = Hop(
        hop_index=1,
        hostname="Aruba-Fallback",
        mgmt_ip="10.0.0.10",
        status="ok",
        ports=[down_port],
        downlink_port=down_port,
    )
    path = UpstreamPath(start_ip="10.0.0.10", hops=[hop], success=True)
    widget.show_path(path)

    cards: list[HopCardWidget] = [
        widget.cards_layout.itemAt(i).widget()
        for i in range(widget.cards_layout.count())
        if isinstance(widget.cards_layout.itemAt(i).widget(), HopCardWidget)
    ]
    summary_frame = cards[0].findChild(QFrame, "path_summary")
    summary_text = " ".join(lbl.text() for lbl in summary_frame.findChildren(QLabel))

    assert "PVID 1" in summary_text
    assert "UNTAGGED 1" in summary_text
    assert "TAGGED 30" in summary_text
    assert down_port.pvid is None  # real pvid not overwritten
    assert down_port.effective_pvid == 1

    widget.close()


def test_upstream_widget_render_aruba_mesh_candidate():
    """Verify that Aruba claimed root with mesh candidate renders warning tag,
    candidate prompt, and interactive continuation button emitting candidate IP.
    """
    from PySide6.QtWidgets import QFrame, QLabel, QPushButton
    from linksight.discovery.demo import get_aruba_demo_path

    app = QApplication.instance() or QApplication([])
    widget = UpstreamWidget()
    widget.show()

    emitted: list[str] = []
    widget.continue_from.connect(lambda ip: emitted.append(ip))

    path = get_aruba_demo_path()
    widget.show_path(path)

    cards: list[HopCardWidget] = [
        widget.cards_layout.itemAt(i).widget()
        for i in range(widget.cards_layout.count())
        if isinstance(widget.cards_layout.itemAt(i).widget(), HopCardWidget)
    ]
    assert len(cards) == 1
    aruba_card = cards[0]

    # Verify status tag on card
    card_labels = [lbl.text() for lbl in aruba_card.findChildren(QLabel)]
    assert any("CLAIMED ROOT · MESH UPLINK" in t for t in card_labels)

    # Verify path summary has Port 3
    summary_frame = aruba_card.findChild(QFrame, "path_summary")
    assert summary_frame is not None
    summary_text = " ".join(lbl.text() for lbl in summary_frame.findChildren(QLabel))
    assert "Port 3" in summary_text
    assert "Claimed Root — Mesh Uplink" in summary_text

    # Verify candidate box
    cand_frame = aruba_card.findChild(QFrame, "ambiguous_candidates")
    assert cand_frame is not None
    cand_labels = [lbl.text() for lbl in cand_frame.findChildren(QLabel)]
    assert any("Switch reports STP root, but upstream mesh/LLDP candidate(s) detected" in t for t in cand_labels)

    # Verify candidate button for mesh AP
    cand_btn = aruba_card.findChild(QPushButton, "candidate_btn_10.0.0.1")
    assert cand_btn is not None
    assert "▶ Try Mesh-AP-Backhaul (10.0.0.1) on Port 24" in cand_btn.text()

    # Verify candidate button for UniFi switch on Port 47
    cand_btn_47 = aruba_card.findChild(QPushButton, "candidate_btn_47")
    assert cand_btn_47 is not None
    assert "▶ Try UniFi-Switch (on Port 47)" in cand_btn_47.text()

    # Clicking button emits signal with structured payload
    cand_btn.click()
    assert len(emitted) == 1
    assert emitted[0]["hop_mgmt_ip"] == "10.0.0.10"
    assert emitted[0]["port_id"] == 24
    assert emitted[0]["candidate"].neighbor_ip == "10.0.0.1"

    widget.close()


def test_candidate_button_renders_no_ip_label_format():
    """Verify that HopCardWidget renders candidates without management IP properly,
    including Port 47 with name, or Port with chassis MAC, and clicking emits candidate.
    """
    from PySide6.QtWidgets import QPushButton
    from linksight.discovery.models import Hop, PortDiagnostics, UpstreamPath

    app = QApplication.instance() or QApplication([])

    cand_unifi = PortDiagnostics(
        port_id=47,
        port_name="Port 47",
        neighbor_name="UniFi-Switch",
        neighbor_ip="",
        neighbor_chassis="74:83:c2:11:22:33",
        link_speed_mbps=1000,
    )
    cand_chassis_only = PortDiagnostics(
        port_id=12,
        port_name="Port 12",
        neighbor_name="",
        neighbor_ip="",
        neighbor_chassis="00:11:22:33:44:55",
        link_speed_mbps=1000,
    )

    hop = Hop(
        hop_index=1,
        hostname="Aruba-2930F",
        mgmt_ip="10.0.0.10",
        status="root_claimed_but_uplinks_present",
        ports=[cand_unifi, cand_chassis_only],
        ambiguous_candidates=[cand_unifi, cand_chassis_only],
    )

    widget = UpstreamWidget()
    widget.show()
    widget.show_path(UpstreamPath(start_ip="10.0.0.10", hops=[hop], edge_type="root_claimed_but_uplinks_present", success=False))

    emitted = []
    widget.continue_from.connect(emitted.append)

    cand_btns = [b for b in widget.findChildren(QPushButton) if "▶ Try" in b.text()]
    assert len(cand_btns) == 2
    assert "▶ Try UniFi-Switch (on Port 47)" in cand_btns[0].text()
    assert "▶ Try 00:11:22:33:44:55 (on Port 12)" in cand_btns[1].text()

    # Clicking candidate without IP emits the candidate structured payload
    cand_btns[0].click()
    assert len(emitted) == 1
    assert isinstance(emitted[0], dict)
    assert emitted[0]["port_id"] == 47
    assert emitted[0]["hop_mgmt_ip"] == "10.0.0.10"
    cand_diag = emitted[0]["candidate"]
    assert isinstance(cand_diag, PortDiagnostics)
    assert cand_diag.port_id == 47
    assert cand_diag.neighbor_name == "UniFi-Switch"
    assert cand_diag.neighbor_chassis == "74:83:c2:11:22:33"

    widget.close()


