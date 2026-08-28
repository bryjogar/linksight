"""Synthetic LLDP/CDP frame builders — byte-accurate to the wire specs.

Used by tests as fixtures and by demo mode to simulate a network.
These are synthetic but structurally faithful: real TLV headers, lengths,
subtypes, and payload encodings.
"""

from __future__ import annotations

from .dhcp import DHCP_MAGIC

LLDP_DST = "01:80:c2:00:00:0e"
CDP_DST = "01:00:0c:cc:cc:cc"


def _tlv(tlv_type: int, payload: bytes) -> bytes:
    """2-byte header: 7 bits type, 9 bits length."""
    header = ((tlv_type & 0x7F) << 9) | (len(payload) & 0x1FF)
    return header.to_bytes(2, "big") + payload


def eth(dst: str, src: str, ethertype: int, body: bytes) -> bytes:
    def mac(s: str) -> bytes:
        return bytes(int(x, 16) for x in s.split(":"))

    return mac(dst) + mac(src) + ethertype.to_bytes(2, "big") + body


def build_lldp_frame(
    chassis_mac: str = "00:1a:2b:3c:4d:5e",
    src_mac: str = "00:1a:2b:3c:4d:5e",
    port_id: str = "Gi0/24",
    system_name: str = "Core-SW1",
    system_desc: str = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E, RELEASE SOFTWARE",
    mgmt_ip: str = "10.0.0.2",
    vlan: int = 100,
    capabilities: int = 0x0014,
) -> bytes:
    body = b""
    body += _tlv(1, b"\x04" + bytes(int(x, 16) for x in chassis_mac.split(":")))          # Chassis ID (MAC)
    body += _tlv(2, b"\x05" + port_id.encode())                                            # Port ID (ifname)
    body += _tlv(3, (120).to_bytes(2, "big"))                                              # TTL
    body += _tlv(5, system_name.encode())                                                  # System Name
    body += _tlv(6, system_desc.encode())                                                  # System Description
    body += _tlv(7, capabilities.to_bytes(2, "big") + capabilities.to_bytes(2, "big"))     # Caps
    if mgmt_ip:
        ip = bytes(int(x) for x in mgmt_ip.split("."))
        # 802.1AB mgmt address: len(1)=5 subtype(1)=IPv4 addr(4) iface_subtype(1) iface_num(4) oid_len(1)
        body += _tlv(8, b"\x05\x01" + ip + b"\x01\x00\x00\x00\x01\x00")
    if vlan is not None:
        body += _tlv(127, b"\x00\x80\xc2\x01" + vlan.to_bytes(2, "big"))
    body += _tlv(0, b"")
    return eth(LLDP_DST, src_mac, 0x88CC, body)


def build_cdp_frame(
    device_id: str = "Core-SW1",
    src_mac: str = "00:1a:2b:3c:4d:5e",
    port_id: str = "Gi0/24",
    platform: str = "cisco WS-C2960X-24TS-L",
    software: str = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E",
    mgmt_ip: str = "10.0.0.2",
    vlan: int = 100,
    caps: int = 0x09,
    duplex: int = 1,
) -> bytes:
    def cdp_tlv(tlv_type: int, value: bytes) -> bytes:
        return tlv_type.to_bytes(2, "big") + (len(value) + 4).to_bytes(2, "big") + value

    body = b"\x01\x01\x00\x00"  # version=1, ttl=1, checksum=0
    body += cdp_tlv(0x0001, device_id.encode())
    if mgmt_ip:
        ip = bytes(int(x) for x in mgmt_ip.split("."))
        body += cdp_tlv(0x0002, (1).to_bytes(4, "big") + b"\x01\x01\xcc" + (4).to_bytes(2, "big") + ip)
    body += cdp_tlv(0x0003, port_id.encode())
    body += cdp_tlv(0x0004, caps.to_bytes(4, "big"))
    body += cdp_tlv(0x0005, software.encode())
    body += cdp_tlv(0x0006, platform.encode())
    body += cdp_tlv(0x000A, vlan.to_bytes(2, "big"))
    body += cdp_tlv(0x000B, bytes([duplex]))
    return eth(CDP_DST, src_mac, 0x2000, body)


def build_dhcp_frame(
    message_type: int = 2,  # OFFER
    offered_ip: str = "10.0.0.42",
    server_ip: str = "10.0.0.1",
    subnet_mask: str = "255.255.255.0",
    gateways: list[str] | None = None,
    dns_servers: list[str] | None = None,
    lease_seconds: int = 86400,
    client_mac: str = "00:1a:2b:3c:4d:5e",
    src_mac: str = "00:1a:2b:3c:4d:5e",
    xid: int = 0x12345678,
    domain: str = "",
) -> bytes:
    """Build a DHCP OFFER/ACK as a full IPv4/UDP frame (EtherType 0x0800)."""

    def opt(code: int, value: bytes) -> bytes:
        return bytes([code, len(value)]) + value

    def ip4(s: str) -> bytes:
        return bytes(int(x) for x in s.split("."))

    # BOOTP header (236 bytes)
    bootp = bytearray(236)
    bootp[0] = 2  # op: reply
    bootp[1] = 1  # htype: ethernet
    bootp[2] = 6  # hlen
    bootp[4:8] = xid.to_bytes(4, "big")
    bootp[16:20] = ip4(offered_ip)  # yiaddr
    bootp[20:24] = ip4(server_ip) if server_ip else b"\x00\x00\x00\x00"  # siaddr
    macb = bytes(int(x, 16) for x in client_mac.split(":"))
    bootp[28:34] = macb  # chaddr

    # options
    opts = bytearray()
    opts += opt(53, bytes([message_type]))
    opts += opt(54, ip4(server_ip))  # server identifier
    if subnet_mask:
        opts += opt(1, ip4(subnet_mask))
    gws = gateways or [server_ip]
    if gws:
        opts += opt(3, b"".join(ip4(g) for g in gws))
    if dns_servers:
        opts += opt(6, b"".join(ip4(d) for d in dns_servers))
    if domain:
        opts += opt(15, domain.encode())
    opts += opt(51, lease_seconds.to_bytes(4, "big"))
    opts += b"\xff"  # end

    udp_payload = bytes(bootp) + DHCP_MAGIC + bytes(opts)
    return build_udp_frame(src_mac, server_ip, 67, "ff:ff:ff:ff:ff:ff", "255.255.255.255", 68, udp_payload)


def build_udp_frame(
    src_mac: str,
    src_ip: str,
    src_port: int,
    dst_mac: str,
    dst_ip: str,
    dst_port: int,
    udp_payload: bytes,
) -> bytes:
    """Build a minimal IPv4/UDP frame with correct lengths (no checksum)."""
    from struct import pack

    def ip4(s: str) -> bytes:
        return bytes(int(x) for x in s.split("."))

    udp_len = 8 + len(udp_payload)
    udp = pack(">HHHH", src_port, dst_port, udp_len, 0) + udp_payload

    ihl = 5
    total_len = 20 + len(udp)
    ip = bytearray(20)
    ip[0] = 0x45  # IPv4, IHL=5
    ip[2:4] = total_len.to_bytes(2, "big")
    ip[8] = 64  # TTL
    ip[9] = 17  # UDP
    ip[12:16] = ip4(src_ip)
    ip[16:20] = ip4(dst_ip)

    return eth(dst_mac, src_mac, 0x0800, bytes(ip) + udp)
