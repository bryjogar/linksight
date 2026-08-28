"""Tests for the system IP config reader."""

from netprobe.capture.system_info import (
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

   Connection-specific DNS Suffix  . : garrison.lan
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
    import netprobe.capture.system_info as si
    si._run = FakeRun(IPCONFIG_SAMPLE)
    _fill_windows(cfg, "Ethernet 2")

    assert cfg.ip == "10.0.0.42"
    assert cfg.netmask == "255.255.255.0"
    assert cfg.gateway == "10.0.0.1"
    assert cfg.dhcp_server == "10.0.0.1"
    assert cfg.dhcp_enabled is True
    assert cfg.dns_servers == ["8.8.8.8", "1.1.1.1"]


def test_windows_no_match():
    import netprobe.capture.system_info as si
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

    import netprobe.capture.system_info as si

    monkeypatch.setattr(si, "_PROC_ROUTE", str(route))
    monkeypatch.setattr(si, "_RESOLV_CONF", str(resolv))
    cfg = InterfaceConfig(name="enp1s0")
    _fill_linux(cfg)
    assert cfg.gateway == "10.0.0.1"
    assert cfg.dns_servers == ["10.0.0.1", "8.8.8.8"]


def test_config_to_dict():
    cfg = InterfaceConfig(name="eth0", ip="10.0.0.42", dns_servers=["8.8.8.8"])
    d = cfg.to_dict()
    assert d["ip"] == "10.0.0.42"
    assert d["dns_servers"] == ["8.8.8.8"]
