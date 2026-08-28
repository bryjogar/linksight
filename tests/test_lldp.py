"""Tests for the LLDP parser."""

import pytest

from netprobe.parse.lldp import parse_lldp_frame, extract_platform
from netprobe.parse.frames import parse_frame
from netprobe.parse.builders import _tlv, eth, LLDP_DST
from tests.fixtures import build_lldp_frame, LLDP_SAMPLE


def test_lldp_basic_fields():
    dev = parse_lldp_frame(LLDP_SAMPLE, "eth0")
    assert dev is not None
    assert dev.protocol == "lldp"
    assert dev.source_interface == "eth0"
    assert dev.chassis_id == "00:1a:2b:3c:4d:5e"
    assert dev.chassis_id_type == 4
    assert dev.port_id == "Gi0/24"
    assert dev.port_id_type == 5
    assert dev.system_name == "Core-SW1"
    assert "Cisco IOS" in dev.system_description
    assert dev.management_ips == ["10.0.0.2"]
    assert dev.vlan == 100
    assert "Bridge" in dev.capabilities and "Router" in dev.capabilities


def test_lldp_dispatch_via_parse_frame():
    dev = parse_frame(LLDP_SAMPLE, "eth0")
    assert dev is not None
    assert dev.protocol == "lldp"
    assert dev.system_name == "Core-SW1"


def test_lldp_hostname_chassis():
    # Chassis ID subtype 7 (locally assigned) = hostname string
    frame = build_lldp_frame(chassis_mac="00:00:00:00:00:00", system_name="lab-ap-2")
    dev = parse_lldp_frame(frame, "eth0")
    assert dev is not None
    assert dev.system_name == "lab-ap-2"


def test_lldp_rejects_non_lldp():
    junk = b"\x00" * 60
    assert parse_lldp_frame(junk, "eth0") is None


def test_lldp_empty_frame():
    assert parse_lldp_frame(b"", "eth0") is None


def test_lldp_port_description_wins_over_component_id():
    """Regression: HP/Aruba 2920 sends Port ID as opaque component (subtype 2)
    and the real port in the Port Description TLV. NetProbe must show the
    description ("3"), not the raw component bytes."""
    body = b""
    body += _tlv(1, b"\x04" + bytes.fromhex("941882d88440"))       # Chassis ID (MAC)
    body += _tlv(2, b"\x02\x07\x33\x06")                            # Port ID: subtype 2 (component)
    body += _tlv(3, (120).to_bytes(2, "big"))                       # TTL
    body += _tlv(4, b"3")                                           # Port Description: "3"
    body += _tlv(5, b"ThisisLive")                                  # System Name
    body += _tlv(0, b"")                                            # End
    frame = eth(LLDP_DST, "94:18:82:d8:84:7d", 0x88CC, body)

    dev = parse_lldp_frame(frame, "eth0")
    assert dev is not None
    assert dev.system_name == "ThisisLive"
    assert dev.port_id_type == 2
    assert dev.raw_tlvs.get("port_description") == "3"


def test_lldp_mgmt_address_hp_real_frame():
    """Exact bytes from the real HP frame: mgmt address TLV payload
    05 01 c0 a8 04 79 02 00 00 00 00 00 -> 192.168.4.121 (length-first)."""
    body = b""
    body += _tlv(1, b"\x04" + bytes.fromhex("941882d88440"))          # Chassis ID
    body += _tlv(2, b"\x02\x07\x33\x06")                               # Port ID (component)
    body += _tlv(3, (120).to_bytes(2, "big"))                          # TTL
    body += _tlv(8, b"\x05\x01\xc0\xa8\x04\x79" + b"\x02\x00\x00\x00\x00\x00")
    body += _tlv(5, b"ThisisLive")
    body += _tlv(0, b"")
    frame = eth(LLDP_DST, "94:18:82:d8:84:7d", 0x88CC, body)

    dev = parse_lldp_frame(frame, "eth0")
    assert dev is not None
    assert dev.management_ips == ["192.168.4.121"]


def test_lldp_mgmt_address_subtype1_ipv4():
    """Standard length-first subtype 1 IPv4 parses."""
    body = b""
    body += _tlv(1, b"\x04" + bytes.fromhex("001a2b3c4d5e"))
    body += _tlv(2, b"\x05Gi0/1")
    body += _tlv(3, (120).to_bytes(2, "big"))
    body += _tlv(8, b"\x05\x01\x0a\x00\x00\x02" + b"\x01\x00\x00\x00\x01\x00")
    body += _tlv(0, b"")
    dev = parse_lldp_frame(eth(LLDP_DST, "00:1a:2b:3c:4d:5e", 0x88CC, body), "eth0")
    assert dev is not None
    assert dev.management_ips == ["10.0.0.2"]


def test_extract_platform_hp():
    desc = ("HP J9729A 2920-48G-POE+ Switch, revision WB.16.10.0010, "
            "ROM WB.16.03 (/ws/swbuildm/rel_ajanta_qaoff/rel_ajanta))")
    assert extract_platform(desc) == "HP J9729A 2920-48G-POE+ Switch"


def test_extract_platform_cisco():
    desc = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E, RELEASE SOFTWARE"
    assert extract_platform(desc) == "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M)"


def test_extract_platform_short():
    assert extract_platform("netgear GS108") == "netgear GS108"
