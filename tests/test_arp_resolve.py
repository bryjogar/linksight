"""Unit tests for ARP management IP resolution."""

from unittest.mock import MagicMock
import ipaddress

import pytest

from linksight.capture.interfaces import NetInterface
from linksight.discovery.arp_resolve import (
    arp_sweep,
    compute_subnets_for_interface,
    normalize_mac,
    resolve_switch_mgmt_ip,
)
from linksight.parse.model import NeighborDevice


def test_normalize_mac():
    """Verify MAC address normalization across colon, dash, dot, and compact formats."""
    # Colons
    assert normalize_mac("00:1a:2b:3c:4d:5e") == "001a2b3c4d5e"
    assert normalize_mac("00:1A:2B:3C:4D:5E") == "001a2b3c4d5e"

    # Dashes
    assert normalize_mac("00-1a-2b-3c-4d-5e") == "001a2b3c4d5e"
    assert normalize_mac("00-1A-2B-3C-4D-5E") == "001a2b3c4d5e"

    # Dots (Cisco style)
    assert normalize_mac("001a.2b3c.4d5e") == "001a2b3c4d5e"
    assert normalize_mac("001A.2B3C.4D5E") == "001a2b3c4d5e"

    # No separator
    assert normalize_mac("001a2b3c4d5e") == "001a2b3c4d5e"
    assert normalize_mac("001A2B3C4D5E") == "001a2b3c4d5e"

    # Invalid values
    assert normalize_mac("") is None
    assert normalize_mac("Core-SW1") is None
    assert normalize_mac("192.168.1.1") is None
    assert normalize_mac("00:11:22") is None
    assert normalize_mac("00:11:22:33:44:55:66") is None
    assert normalize_mac("zz:zz:zz:zz:zz:zz") is None


def test_compute_subnets_for_interface():
    """Verify subnet computation caps size, skips /8, loopback, and public IPs."""
    # Standard RFC 1918 /24
    nic1 = NetInterface(name="eth0", ips=["192.168.1.50"])
    subnets1 = compute_subnets_for_interface(nic1)
    assert subnets1 == [ipaddress.IPv4Network("192.168.1.0/24")]

    # Explicit CIDR prefix (/23)
    nic2 = NetInterface(name="eth1", ips=["10.10.0.5/23"])
    subnets2 = compute_subnets_for_interface(nic2)
    assert subnets2 == [ipaddress.IPv4Network("10.10.0.0/23")]

    # Large /8 network is skipped to avoid unbounded sweep
    nic_large = NetInterface(name="eth2", ips=["10.0.0.5/8"])
    subnets_large = compute_subnets_for_interface(nic_large)
    assert subnets_large == []

    # Loopback and public addresses are skipped
    nic_ext = NetInterface(name="eth3", ips=["127.0.0.1", "8.8.8.8"])
    subnets_ext = compute_subnets_for_interface(nic_ext)
    assert subnets_ext == []

    # Multiple IPv4s on same adapter
    nic_multi = NetInterface(name="eth4", ips=["192.168.1.10", "172.16.5.20"])
    subnets_multi = compute_subnets_for_interface(nic_multi)
    assert subnets_multi == [
        ipaddress.IPv4Network("192.168.1.0/24"),
        ipaddress.IPv4Network("172.16.5.0/24"),
    ]


def test_arp_sweep_mock_transport():
    """Verify arp_sweep maps replies to normalized MAC -> IP and handles errors gracefully."""
    # Successful mock transport returning dict
    transport = MagicMock(return_value={"74:83:c2:11:22:33": "192.168.1.20"})
    result = arp_sweep("eth0", subnets=["192.168.1.0/24"], transport=transport)
    assert result == {"7483c2112233": "192.168.1.20"}

    # Mock transport raising error degrades gracefully without raising
    err_transport = MagicMock(side_effect=OSError("Npcap not available"))
    err_result = arp_sweep("eth0", subnets=["192.168.1.0/24"], transport=err_transport)
    assert err_result == {}


def test_resolve_switch_mgmt_ip_chassis_mac_match():
    """(a) chassis MAC match -> returns resolved IP."""
    dev = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        chassis_id="74:83:c2:11:22:33",
        system_name="USW-Lite-16-PoE",
        management_ips=[],
    )
    nic = NetInterface(name="eth0", ips=["192.168.1.100"], is_up=True)
    mock_sweep = MagicMock(return_value={
        "74:83:c2:11:22:33": "192.168.1.20",
        "00:11:22:33:44:55": "192.168.1.1",
    })

    ip = resolve_switch_mgmt_ip(dev, sweep_fn=mock_sweep, ifaces=[nic])
    assert ip == "192.168.1.20"
    mock_sweep.assert_called_once()


def test_resolve_switch_mgmt_ip_no_match():
    """(b) no match -> returns None."""
    dev = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        chassis_id="74:83:c2:11:22:33",
        system_name="USW-Lite-16-PoE",
        management_ips=[],
    )
    nic = NetInterface(name="eth0", ips=["192.168.1.100"], is_up=True)
    mock_sweep = MagicMock(return_value={
        "00:11:22:33:44:55": "192.168.1.1",
        "aa:bb:cc:dd:ee:ff": "192.168.1.254",
    })

    ip = resolve_switch_mgmt_ip(dev, sweep_fn=mock_sweep, ifaces=[nic])
    assert ip is None
    mock_sweep.assert_called_once()


def test_resolve_switch_mgmt_ip_already_has_mgmt_ip():
    """(c) device already has LLDP mgmt IP -> no sweep attempted."""
    dev = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        chassis_id="00:1a:2b:3c:4d:5e",
        system_name="Core-SW1",
        management_ips=["10.0.0.2"],
    )
    nic = NetInterface(name="eth0", ips=["10.0.0.100"], is_up=True)
    mock_sweep = MagicMock()

    ip = resolve_switch_mgmt_ip(dev, sweep_fn=mock_sweep, ifaces=[nic])
    assert ip is None
    mock_sweep.assert_not_called()


def test_resolve_switch_mgmt_ip_mac_normalization():
    """(d) MAC normalization (colon/dash/no-separator forms match)."""
    nic = NetInterface(name="eth0", ips=["192.168.1.100"], is_up=True)

    # 1. Device has dashed MAC, sweep returns colon MAC
    dev1 = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        chassis_id="74-83-C2-11-22-33",
        management_ips=[],
    )
    sweep1 = lambda iface, **kw: {"74:83:c2:11:22:33": "192.168.1.20"}
    assert resolve_switch_mgmt_ip(dev1, sweep_fn=sweep1, ifaces=[nic]) == "192.168.1.20"

    # 2. Device has no separators, sweep returns dashed MAC
    dev2 = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        chassis_id="7483c2112233",
        management_ips=[],
    )
    sweep2 = lambda iface, **kw: {"74-83-c2-11-22-33": "192.168.1.20"}
    assert resolve_switch_mgmt_ip(dev2, sweep_fn=sweep2, ifaces=[nic]) == "192.168.1.20"

    # 3. Device has colon MAC, sweep returns no separators
    dev3 = NeighborDevice(
        protocol="lldp",
        source_interface="eth0",
        chassis_id="74:83:c2:11:22:33",
        management_ips=[],
    )
    sweep3 = lambda iface, **kw: {"7483C2112233": "192.168.1.20"}
    assert resolve_switch_mgmt_ip(dev3, sweep_fn=sweep3, ifaces=[nic]) == "192.168.1.20"


def test_resolve_switch_mgmt_ip_interface_fallback():
    """Verify fallback to preferred_interface when source_interface is not up."""
    dev = NeighborDevice(
        protocol="lldp",
        source_interface="down-nic",
        chassis_id="74:83:c2:11:22:33",
        management_ips=[],
    )
    down_nic = NetInterface(name="down-nic", ips=["10.0.0.10"], is_up=False)
    up_nic = NetInterface(name="eth0", description="Ethernet Adapter", ips=["192.168.1.50"], is_up=True)

    sweep = MagicMock(return_value={"7483c2112233": "192.168.1.20"})
    ip = resolve_switch_mgmt_ip(dev, sweep_fn=sweep, ifaces=[down_nic, up_nic])
    assert ip == "192.168.1.20"
    sweep.assert_called_once()
    # Verify swept on the up_nic
    assert sweep.call_args[0][0] == "eth0"


def test_resolve_switch_mgmt_ip_invalid_chassis_mac():
    """Verify non-MAC chassis_id (e.g. hostname) skips sweep."""
    dev = NeighborDevice(
        protocol="cdp",
        source_interface="eth0",
        chassis_id="Core-SW1",
        management_ips=[],
    )
    nic = NetInterface(name="eth0", ips=["192.168.1.100"], is_up=True)
    sweep = MagicMock()

    ip = resolve_switch_mgmt_ip(dev, sweep_fn=sweep, ifaces=[nic])
    assert ip is None
    sweep.assert_not_called()
