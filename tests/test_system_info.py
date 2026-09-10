"""Tests for the system IP config reader."""

from linksight.capture.system_info import (
    InterfaceConfig,
    _fill_windows,
    _fill_linux,
)


class FakeRun:
    def __init__(self, out: str):
        self.out = out

    def __call__(self, cmd, timeout=8) -> str:
        return self.out


IPCONFIG_SAMPLE = r"""
Windows IP Configuration

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : example.lan
   Description . . . . . . . . . . . : USB 10/100/1000 LAN
   Physical Address. . . . . . . . . : 22-77-EE-AD-6C-EE
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.0.0.42(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Thursday, August 13, 2026 9:00:00 AM
   Lease Expires . . . . . . . . . . : Friday, August 14, 2026 9:00:00 AM
   Default Gateway . . . . . . . . . : 10.0.0.1
   DHCP Server . . . . . . . . . . . : 10.0.0.1
   DNS Servers . . . . . . . . . . . : 8.8.8.8
                                       1.1.1.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Wireless LAN adapter Wi-Fi:

   Media State . . . . . . . . . . . : Media disconnected
"""


def test_windows_ipconfig_parse():
    """Parse ipconfig /all for the Ethernet adapter block."""
    cfg = InterfaceConfig(name="Ethernet 2")
    _fill_windows(cfg, "Ethernet 2")
    # patch subprocess via module-level _run
    import linksight.capture.system_info as si
    si._run = FakeRun(IPCONFIG_SAMPLE)
    _fill_windows(cfg, "Ethernet 2")

    assert cfg.ip == "10.0.0.42"
    assert cfg.netmask == "255.255.255.0"
    assert cfg.gateway == "10.0.0.1"
    assert cfg.dhcp_server == "10.0.0.1"
    assert cfg.dhcp_enabled is True
    assert cfg.dns_servers == ["8.8.8.8", "1.1.1.1"]


def test_windows_no_match():
    import linksight.capture.system_info as si
    si._run = FakeRun(IPCONFIG_SAMPLE)
    cfg = InterfaceConfig(name="Nonexistent Adapter")
    _fill_windows(cfg, "Nonexistent Adapter")
    assert cfg.ip == ""
    assert cfg.dhcp_enabled is None


def test_linux_gateway_and_dns(tmp_path, monkeypatch):
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "enp1s0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "enp1s0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
    )
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 10.0.0.1\nnameserver 8.8.8.8\n")

    import linksight.capture.system_info as si


    monkeypatch.setattr(si, "_PROC_ROUTE", str(route))
    monkeypatch.setattr(si, "_RESOLV_CONF", str(resolv))
    cfg = InterfaceConfig(name="enp1s0")
    _fill_linux(cfg)
    assert cfg.gateway == "10.0.0.1"
    assert cfg.dns_servers == ["10.0.0.1", "8.8.8.8"]


def test_config_to_dict():
    cfg = InterfaceConfig(name="eth0", ip="10.0.0.42", dns_servers=["8.8.8.8"], unavailable_reason="no output")
    d = cfg.to_dict()
    assert d["ip"] == "10.0.0.42"
    assert d["dns_servers"] == ["8.8.8.8"]
    assert d["unavailable_reason"] == "no output"


POWERSHELL_SAMPLE = r"""
{
    "InterfaceAlias": "Ethernet",
    "InterfaceIndex": 12,
    "IPv4Address": {
        "IPAddress": "192.168.1.150",
        "PrefixLength": 24
    },
    "IPv4DefaultGateway": {
        "NextHop": "192.168.1.1"
    },
    "DNSServer": {
        "ServerAddresses": [
            "1.1.1.1",
            "1.0.0.1"
        ]
    },
    "DhcpServer": "192.168.1.1",
    "NetIPv4Interface": {
        "DHCP": "Enabled"
    }
}
"""

IPCONFIG_VETHERNET_PRECEDENCE_SAMPLE = r"""
Windows IP Configuration

Ethernet adapter vEthernet (Default Switch):

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter
   Physical Address. . . . . . . . . : 00-15-5D-12-34-56
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 172.28.16.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . :
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : corp.local
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection I219-LM
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.42(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.254
   DNS Servers . . . . . . . . . . . : 8.8.8.8
                                       8.8.4.4
   NetBIOS over Tcpip. . . . . . . . : Enabled
"""


def test_windows_powershell_happy_path(monkeypatch):
    """PowerShell Get-NetIPConfiguration parses IPv4, mask, gateway, DNS, and DHCP."""
    import linksight.capture.system_info as si

    monkeypatch.setattr(si, "_run", lambda cmd, timeout=8: POWERSHELL_SAMPLE if "powershell" in cmd[0] else None)
    cfg = InterfaceConfig(name="Ethernet")
    _fill_windows(cfg, "Ethernet")

    assert cfg.ip == "192.168.1.150"
    assert cfg.netmask == "255.255.255.0"
    assert cfg.gateway == "192.168.1.1"
    assert cfg.dns_servers == ["1.1.1.1", "1.0.0.1"]
    assert cfg.dhcp_server == "192.168.1.1"
    assert cfg.dhcp_enabled is True
    assert cfg.unavailable_reason == ""


def test_windows_ipconfig_vethernet_precedence(monkeypatch):
    """Exact header match must select 'Ethernet' over preceding 'vEthernet (Default Switch)'."""
    import linksight.capture.system_info as si

    def fake_run(cmd, timeout=8):
        if "powershell" in cmd[0]:
            return None  # fall through to ipconfig
        return IPCONFIG_VETHERNET_PRECEDENCE_SAMPLE

    monkeypatch.setattr(si, "_run", fake_run)
    cfg = InterfaceConfig(name="Ethernet")
    _fill_windows(cfg, "Ethernet")

    assert cfg.ip == "192.168.1.42"
    assert cfg.netmask == "255.255.255.0"
    assert cfg.gateway == "192.168.1.1"
    assert cfg.dhcp_server == "192.168.1.254"
    assert cfg.dns_servers == ["8.8.8.8", "8.8.4.4"]
    assert cfg.dhcp_enabled is True
    assert cfg.unavailable_reason == ""


def test_windows_run_failing_preserves_psutil_and_reports_unavailable(monkeypatch):
    """When subprocess fails or returns empty, psutil data survives and unavailable is reported."""
    import linksight.capture.system_info as si
    from PySide6.QtWidgets import QApplication, QLabel
    from linksight.ui.lan_info_widget import LanInfoWidget

    app = QApplication.instance() or QApplication([])

    for fail_val in [None, ""]:
        monkeypatch.setattr(si, "_run", lambda cmd, timeout=8: fail_val)
        cfg = InterfaceConfig(
            name="Ethernet",
            mac="00:11:22:33:44:55",
            ip="192.168.1.10",
            netmask="255.255.255.0",
        )
        _fill_windows(cfg, "Ethernet")

        # Psutil values survived
        assert cfg.ip == "192.168.1.10"
        assert cfg.netmask == "255.255.255.0"
        assert cfg.mac == "00:11:22:33:44:55"
        # Gateway / DNS / DHCP were not populated
        assert cfg.gateway == ""
        assert cfg.dns_servers == []
        assert cfg.dhcp_server == ""
        # Explicit unavailable reason is set
        assert cfg.unavailable_reason in ("command failed", "no output")

        # UI panel displays the unavailable state
        widget = LanInfoWidget()
        try:
            widget._cached_cfg = cfg
            widget._iface_name = "Ethernet"
            widget._render_current()

            labels = [lbl.text() for lbl in widget.findChildren(QLabel)]
            full_text = " ".join(labels)
            assert "OS config unavailable" in full_text
            assert cfg.unavailable_reason in full_text
        finally:
            widget.close()
