"""Unit tests for ping-based link reachability checks."""

from __future__ import annotations

import subprocess
import threading
import pytest
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication

from linksight.capture.link_checks import (
    LinkCheckResult,
    build_ping_cmd,
    parse_ping_result,
    run_ping,
    run_all_link_checks,
)
from linksight.capture.system_info import InterfaceConfig
from linksight.ui.lan_info_widget import LanInfoWidget
from linksight.ui.theme import OK, WARN, DANGER, FG_FAINT


def test_build_ping_cmd_windows():
    """Windows ping flags: -n 1 -w 1000."""
    cmd = build_ping_cmd("8.8.8.8", platform="win32")
    assert cmd == ["ping", "-n", "1", "-w", "1000", "8.8.8.8"]


def test_build_ping_cmd_linux_and_macos():
    """Linux and macOS ping flags: -c 1 -W 1."""
    cmd_linux = build_ping_cmd("8.8.8.8", platform="linux")
    assert cmd_linux == ["ping", "-c", "1", "-W", "1", "8.8.8.8"]

    cmd_darwin = build_ping_cmd("8.8.8.8", platform="darwin")
    assert cmd_darwin == ["ping", "-c", "1", "-W", "1", "8.8.8.8"]


def test_parse_ping_result_success_linux():
    """Linux successful ping with reply token and latency."""
    out = (
        "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n"
        "64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=14.2 ms\n"
        "\n"
        "--- 8.8.8.8 ping statistics ---\n"
        "1 packets transmitted, 1 received, 0% packet loss, time 0ms\n"
    )
    proc = subprocess.CompletedProcess(args=["ping"], returncode=0, stdout=out, stderr="")
    res = parse_ping_result("8.8.8.8", proc)

    assert res.status == "reachable"
    assert res.is_success is True
    assert res.message == "reachable"
    assert res.latency_ms == 14.2
    assert res.display_text == "reachable (14 ms)"


def test_parse_ping_result_success_windows():
    """Windows successful ping with Reply from and bytes= tokens."""
    out = (
        "Pinging 8.8.8.8 with 32 bytes of data:\n"
        "Reply from 8.8.8.8: bytes=32 time=15ms TTL=116\n"
        "\n"
        "Ping statistics for 8.8.8.8:\n"
        "    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\n"
    )
    proc = subprocess.CompletedProcess(args=["ping"], returncode=0, stdout=out, stderr="")
    res = parse_ping_result("8.8.8.8", proc)

    assert res.status == "reachable"
    assert res.is_success is True
    assert res.message == "reachable"
    assert res.latency_ms == 15.0
    assert res.display_text == "reachable (15 ms)"


def test_parse_ping_result_success_sub_millisecond():
    """Sub-millisecond latency formatted with '<1 ms'."""
    out = "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms\n"
    proc = subprocess.CompletedProcess(args=["ping"], returncode=0, stdout=out, stderr="")
    res = parse_ping_result("127.0.0.1", proc)

    assert res.status == "reachable"
    assert res.latency_ms == 0.045
    assert res.display_text == "reachable (<1 ms)"


def test_parse_ping_result_unreachable_host():
    """Destination host unreachable detected regardless of return code."""
    out = (
        "PING 192.168.1.250 (192.168.1.250) 56(84) bytes of data.\n"
        "From 192.168.1.1 icmp_seq=1 Destination Host Unreachable\n"
        "1 packets transmitted, 0 received, +1 errors, 100% packet loss\n"
    )
    proc = subprocess.CompletedProcess(args=["ping"], returncode=1, stdout=out, stderr="")
    res = parse_ping_result("192.168.1.250", proc)

    assert res.status == "unreachable"
    assert res.message == "unreachable"
    assert res.is_success is False


def test_parse_ping_result_unreachable_dns():
    """DNS resolution failures on Linux, macOS, and Windows."""
    # Linux
    proc_linux = subprocess.CompletedProcess(
        args=["ping"], returncode=2, stdout="", stderr="ping: google.com: Name or service not known\n"
    )
    res_linux = parse_ping_result("google.com", proc_linux)
    assert res_linux.status == "unreachable"
    assert res_linux.message == "unreachable"

    # macOS
    proc_mac = subprocess.CompletedProcess(
        args=["ping"], returncode=1, stdout="", stderr="ping: cannot resolve google.com: Unknown host\n"
    )
    res_mac = parse_ping_result("google.com", proc_mac)
    assert res_mac.status == "unreachable"
    assert res_mac.message == "unreachable"

    # Windows
    proc_win = subprocess.CompletedProcess(
        args=["ping"],
        returncode=1,
        stdout="Ping request could not find host google.com. Please check the name and try again.\n",
        stderr="",
    )
    res_win = parse_ping_result("google.com", proc_win)
    assert res_win.status == "unreachable"
    assert res_win.message == "unreachable"


def test_parse_ping_result_timeout_linux_and_windows():
    """Timeouts labeled distinctly as 'no reply (ICMP may be blocked)'."""
    # Linux packet loss timeout without unreachable error
    out_linux = (
        "PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.\n"
        "--- 192.0.2.1 ping statistics ---\n"
        "1 packets transmitted, 0 received, 100% packet loss, time 0ms\n"
    )
    proc_linux = subprocess.CompletedProcess(args=["ping"], returncode=1, stdout=out_linux, stderr="")
    res_linux = parse_ping_result("192.0.2.1", proc_linux)
    assert res_linux.status == "timeout"
    assert res_linux.message == "no reply (ICMP may be blocked)"

    # Windows request timed out
    out_win = (
        "Pinging 192.0.2.1 with 32 bytes of data:\n"
        "Request timed out.\n"
        "    Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),\n"
    )
    proc_win = subprocess.CompletedProcess(args=["ping"], returncode=1, stdout=out_win, stderr="")
    res_win = parse_ping_result("192.0.2.1", proc_win)
    assert res_win.status == "timeout"
    assert res_win.message == "no reply (ICMP may be blocked)"

    # Subprocess TimeoutExpired returncode 124
    proc_124 = subprocess.CompletedProcess(args=["ping"], returncode=124, stdout="", stderr="timed out")
    res_124 = parse_ping_result("192.0.2.1", proc_124)
    assert res_124.status == "timeout"
    assert res_124.message == "no reply (ICMP may be blocked)"


def test_parse_ping_result_command_unavailable():
    """Missing or failing ping executable reports 'command unavailable'."""
    res = parse_ping_result("8.8.8.8", None)
    assert res.status == "unavailable"
    assert res.message == "command unavailable"


def test_parse_ping_result_no_gateway():
    """Missing gateway target reports 'not checked (no gateway known)', not failed."""
    for empty_target in (None, "", "   ", "0.0.0.0"):
        res = parse_ping_result(empty_target, None)
        assert res.status == "not_checked"
        assert res.message == "not checked (no gateway known)"


def test_run_ping_hardened_subprocess_mocked(monkeypatch):
    """run_ping routes through _safe_run with check_returncode=False."""
    recorded_calls = []

    def fake_safe_run(cmd, timeout=8, check_returncode=True):
        recorded_calls.append((cmd, timeout, check_returncode))
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=12.0 ms\n",
            stderr="",
        )

    monkeypatch.setattr("linksight.capture.link_checks._safe_run", fake_safe_run)

    res = run_ping("8.8.8.8", platform="linux", timeout=3)
    assert len(recorded_calls) == 1
    cmd, timeout, check_returncode = recorded_calls[0]
    assert cmd == ["ping", "-c", "1", "-W", "1", "8.8.8.8"]
    assert timeout == 3
    assert check_returncode is False
    assert res.status == "reachable"
    assert res.latency_ms == 12.0


def test_run_ping_empty_target_skips_subprocess(monkeypatch):
    """run_ping with no target immediately returns without calling subprocess."""
    called = []
    monkeypatch.setattr("linksight.capture.link_checks._safe_run", lambda *a, **k: called.append(True))

    res = run_ping(None)
    assert called == []
    assert res.status == "not_checked"
    assert res.message == "not checked (no gateway known)"


def test_run_all_link_checks_targets(monkeypatch):
    """run_all_link_checks runs DNS+internet, Internet, and ISP gateway."""
    pinged_targets = {}

    def fake_run_ping(tgt, platform=None, timeout=3):
        if tgt is None:
            return LinkCheckResult(target=None, status="not_checked", message="not checked (no gateway known)")
        if tgt == "google.com":
            return LinkCheckResult(target=tgt, status="reachable", message="reachable", latency_ms=18.0)
        if tgt == "8.8.8.8":
            return LinkCheckResult(target=tgt, status="reachable", message="reachable", latency_ms=15.0)
        if tgt == "192.168.1.1":
            return LinkCheckResult(target=tgt, status="timeout", message="no reply (ICMP may be blocked)")
        return LinkCheckResult(target=tgt, status="unreachable", message="unreachable")

    monkeypatch.setattr("linksight.capture.link_checks.run_ping", fake_run_ping)

    # With gateway
    results = run_all_link_checks(gateway="192.168.1.1")
    assert set(results.keys()) == {"DNS + internet", "Internet", "ISP"}
    assert results["DNS + internet"].status == "reachable"
    assert results["Internet"].status == "reachable"
    assert results["ISP"].status == "timeout"
    assert results["ISP"].message == "no reply (ICMP may be blocked)"

    # Without gateway
    results_no_gw = run_all_link_checks(gateway=None)
    assert results_no_gw["ISP"].status == "not_checked"
    assert results_no_gw["ISP"].message == "not checked (no gateway known)"


def test_lan_info_widget_renders_link_checks_ui(monkeypatch):
    """Verify LanInfoWidget displays the three reachability rows with distinct states and colors."""
    app = QApplication.instance() or QApplication([])

    def fake_get_cfg(iface_name: str) -> InterfaceConfig:
        return InterfaceConfig(
            name=iface_name,
            ip="192.168.1.50",
            netmask="255.255.255.0",
            gateway="192.168.1.1",
            dns_servers=["1.1.1.1"],
        )

    def fake_link_checks(gateway=None, platform=None, stop_event=None):
        return {
            "DNS + internet": LinkCheckResult(
                target="google.com", status="reachable", message="reachable", latency_ms=16.0
            ),
            "Internet": LinkCheckResult(
                target="8.8.8.8", status="timeout", message="no reply (ICMP may be blocked)"
            ),
            "ISP": LinkCheckResult(
                target=gateway, status="unreachable", message="unreachable"
            ),
        }

    monkeypatch.setattr("linksight.ui.lan_info_widget.get_interface_config", fake_get_cfg)
    monkeypatch.setattr("linksight.ui.lan_info_widget.run_all_link_checks", fake_link_checks)

    widget = LanInfoWidget()
    try:
        widget.set_interface("eth0")
        assert widget._worker is not None
        widget._worker.wait(2000)
        QCoreApplication.processEvents()

        # Find rendered rows in grid layout
        grid_rows = {}
        for row_idx in range(widget.grid.rowCount()):
            lbl_item = widget.grid.itemAtPosition(row_idx, 0)
            val_item = widget.grid.itemAtPosition(row_idx, 1)
            if lbl_item and val_item and lbl_item.widget() and val_item.widget():
                grid_rows[lbl_item.widget().text()] = val_item.widget()

        assert "DNS + internet" in grid_rows
        assert "Internet" in grid_rows
        assert "ISP" in grid_rows

        dns_val = grid_rows["DNS + internet"]
        assert dns_val.text() == "reachable (16 ms)"
        assert OK in dns_val.styleSheet()

        inet_val = grid_rows["Internet"]
        assert inet_val.text() == "no reply (ICMP may be blocked)"
        assert WARN in inet_val.styleSheet()

        isp_val = grid_rows["ISP"]
        assert isp_val.text() == "unreachable"
        assert DANGER in isp_val.styleSheet()

    finally:
        widget.close()


def test_lan_info_widget_discovered_gateway_handling(monkeypatch):
    """Verify LanInfoWidget accepts discovered switch gateway and triggers background refresh."""
    app = QApplication.instance() or QApplication([])

    def fake_get_cfg(iface_name: str) -> InterfaceConfig:
        return InterfaceConfig(name=iface_name, ip="10.0.0.5", gateway="10.0.0.1")

    monkeypatch.setattr("linksight.ui.lan_info_widget.get_interface_config", fake_get_cfg)
    monkeypatch.setattr(
        "linksight.ui.lan_info_widget.run_all_link_checks",
        lambda gateway=None, platform=None, stop_event=None: {
            "DNS + internet": LinkCheckResult(target="google.com", status="reachable", message="reachable"),
            "Internet": LinkCheckResult(target="8.8.8.8", status="reachable", message="reachable"),
            "ISP": LinkCheckResult(target=gateway, status="reachable", message="reachable"),
        },
    )

    widget = LanInfoWidget()
    try:
        widget.set_interface("eth0")
        if widget._worker:
            widget._worker.wait(2000)
        QCoreApplication.processEvents()

        assert widget._discovered_gateway is None
        widget.set_discovered_gateway("10.0.0.254")
        assert widget._discovered_gateway == "10.0.0.254"

    finally:
        widget.close()
