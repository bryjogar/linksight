"""Tests for interface discovery."""

from netprobe.capture.interfaces import (
    list_interfaces, NetInterface, preferred_interface,
)


def test_list_interfaces_returns_something():
    """On any supported platform there should be at least loopback."""
    ifaces = list_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    assert all(isinstance(i, NetInterface) for i in ifaces)
    assert any(i.name for i in ifaces)


def test_interfaces_have_sane_shapes():
    for iface in list_interfaces():
        assert isinstance(iface.name, str) and iface.name
        assert isinstance(iface.ips, list)
        assert isinstance(iface.is_loopback, bool)
        assert isinstance(iface.label(), str)


def test_loopback_detected():
    ifaces = [i for i in list_interfaces() if i.name.lower().startswith(("lo", "loopback"))]
    if ifaces:
        assert ifaces[0].is_loopback


def _nic(name, ips=(), desc="", loopback=False):
    return NetInterface(name=name, mac="", ips=list(ips), description=desc,
                        is_loopback=loopback)


def test_prefers_ethernet_over_bluetooth():
    """The Bryan-laptop scenario: Bluetooth + Wi-Fi + USB ethernet."""
    ifaces = [
        _nic("Bluetooth Network Connection", desc="Bluetooth Device (Personal Area Network)"),
        _nic("Wi-Fi", ips=["192.168.1.5"], desc="Intel(R) Wi-Fi 6 AX201"),
        _nic("Ethernet 2", ips=["10.0.0.42"], desc="USB 10/100/1000 LAN"),
        _nic("Loopback Pseudo-Interface 1", ips=["127.0.0.1"], loopback=True),
    ]
    assert preferred_interface(ifaces).name == "Ethernet 2"


def test_prefers_ethernet_without_ip_over_wifi_with_ip():
    """Ethernet is the right target even if it currently has no lease."""
    ifaces = [
        _nic("Wi-Fi", ips=["192.168.1.5"]),
        _nic("Ethernet", desc="Realtek PCIe GbE Family Controller"),
    ]
    assert preferred_interface(ifaces).name == "Ethernet"


def test_apipa_ethernet_still_beats_wifi():
    """LLDP works at L2 even without a DHCP lease, so ethernet with APIPA
    is still the right capture target over Wi-Fi."""
    ifaces = [
        _nic("Ethernet", ips=["169.254.10.20"], desc="Realtek PCIe GbE"),
        _nic("Wi-Fi", ips=["192.168.1.5"]),
    ]
    assert preferred_interface(ifaces).name == "Ethernet"


def test_prefers_ethernet_with_real_ip_over_apipa_ethernet():
    """Between two ethernet adapters, the one with a real lease wins."""
    ifaces = [
        _nic("Ethernet", ips=["169.254.10.20"], desc="Realtek PCIe GbE"),
        _nic("Ethernet 2", ips=["10.0.0.42"], desc="USB 10/100/1000 LAN"),
    ]
    assert preferred_interface(ifaces).name == "Ethernet 2"


def test_returns_none_on_empty():
    assert preferred_interface([]) is None
