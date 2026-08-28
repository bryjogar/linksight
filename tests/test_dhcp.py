"""Tests for the DHCP parser."""

from netprobe.parse.dhcp import parse_dhcp, MSG_OFFER, MSG_ACK, MSG_DISCOVER
from netprobe.parse.builders import build_dhcp_frame, build_udp_frame


def test_parse_offer():
    frame = build_dhcp_frame(
        message_type=MSG_OFFER,
        offered_ip="10.0.0.42",
        server_ip="10.0.0.1",
        subnet_mask="255.255.255.0",
        gateways=["10.0.0.1"],
        dns_servers=["8.8.8.8", "1.1.1.1"],
        lease_seconds=86400,
    )
    # DHCP is IPv4/UDP; strip eth+ip+udp headers (14 + 20 + 8)
    payload = frame[14 + 20 + 8 :]
    obs = parse_dhcp(payload, src_ip="10.0.0.1")
    assert obs is not None
    assert obs.message_type == "OFFER"
    assert obs.offered_ip == "10.0.0.42"
    assert obs.server_ip == "10.0.0.1"
    assert obs.subnet_mask == "255.255.255.0"
    assert obs.gateways == ["10.0.0.1"]
    assert obs.dns_servers == ["8.8.8.8", "1.1.1.1"]
    assert obs.lease_seconds == 86400
    assert obs.client_mac == "00:1a:2b:3c:4d:5e"
    assert obs.is_reply


def test_parse_ack():
    frame = build_dhcp_frame(message_type=MSG_ACK)
    payload = frame[14 + 20 + 8 :]
    obs = parse_dhcp(payload)
    assert obs is not None
    assert obs.message_type == "ACK"


def test_rejects_discover():
    """Client DISCOVER has no server-provided info; we still parse type."""
    frame = build_dhcp_frame(message_type=MSG_DISCOVER, offered_ip="0.0.0.0")
    payload = frame[14 + 20 + 8 :]
    obs = parse_dhcp(payload, src_ip="0.0.0.0")
    assert obs is not None
    assert obs.message_type == "DISCOVER"
    assert not obs.is_reply


def test_rejects_non_dhcp():
    assert parse_dhcp(b"\x00" * 100, "1.2.3.4") is None
    assert parse_dhcp(b"", "1.2.3.4") is None


def test_udp_frame_builder_shape():
    """Sanity: the frame builder produces a well-formed Ethernet/IP/UDP frame."""
    frame = build_udp_frame(
        "00:aa:bb:cc:dd:ee", "10.0.0.1", 67,
        "ff:ff:ff:ff:ff:ff", "255.255.255.255", 68,
        b"hello",
    )
    assert frame[12:14] == b"\x08\x00"  # IPv4
    assert frame[14] == 0x45            # IPv4 header
    assert frame[14 + 9] == 17          # UDP
