"""CDP (Cisco Discovery Protocol) TLV parser.

Frame format:
  Ethernet II: dst 01:00:0c:cc:cc:cc, src <mac>, EtherType 0x2000 (SNAP-encapsulated
  LLC: DSAP/SSAP 0xAA, Ctrl 0x03, OUI 00:00:0c, PID 0x2000)
  CDP header: version(1) ttl(1) checksum(2)
  TLVs: type(2) length(2, incl. header) value
"""

from __future__ import annotations

from .model import NeighborDevice
from ..text_util import decode_text as _decode_text, decode_port_id as _decode_port_id

CDP_DST = "01:00:0c:cc:cc:cc"
CDP_SNAP = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"  # LLC SNAP + PID 0x2000

TLV_DEVICE_ID = 0x0001
TLV_ADDRESSES = 0x0002
TLV_PORT_ID = 0x0003
TLV_CAPABILITIES = 0x0004
TLV_SOFTWARE_VERSION = 0x0005
TLV_PLATFORM = 0x0006
TLV_NATIVE_VLAN = 0x000A
TLV_DUPLEX = 0x000B

CAPABILITY_BITS = [
    (0x01, "L3 Router"),
    (0x02, "Transparent Bridge"),
    (0x04, "Source-route Bridge"),
    (0x08, "L2 Switch"),
    (0x10, "Host"),
    (0x20, "IGMP Filter"),
    (0x40, "Repeater"),
    (0x80, "Phone"),
    (0x100, "Remote"),
]


def _read_tlv(buf: bytes, offset: int) -> tuple[int, int, bytes, int] | None:
    if offset + 4 > len(buf):
        return None
    tlv_type = int.from_bytes(buf[offset : offset + 2], "big")
    length = int.from_bytes(buf[offset + 2 : offset + 4], "big")
    if length < 4:
        return None
    start = offset + 4
    end = start + (length - 4)
    if end > len(buf):
        return None
    return tlv_type, length, buf[start:end], end


def _caps(payload: bytes) -> list[str]:
    if len(payload) < 4:
        return []
    bits = int.from_bytes(payload[:4], "big")
    return [name for mask, name in CAPABILITY_BITS if bits & mask]


def _addresses(payload: bytes) -> list[str]:
    """CDP address TLV: num_addrs(4), then per addr:
    proto_type(1) proto_len(1) proto[proto_len] addr_len(2) addr[addr_len]
    """
    out: list[str] = []
    if len(payload) < 4:
        return out
    num = int.from_bytes(payload[:4], "big")
    off = 4
    for _ in range(min(num, 16)):
        if off + 4 > len(payload):
            break
        ptype = payload[off]
        plen = payload[off + 1]
        if off + 2 + plen > len(payload):
            break
        proto = payload[off + 2 : off + 2 + plen]
        off += 2 + plen
        if off + 2 > len(payload):
            break
        alen = int.from_bytes(payload[off : off + 2], "big")
        off += 2
        if off + alen > len(payload):
            break
        addr = payload[off : off + alen]
        off += alen
        # NLPID 0xcc = IP
        if ptype == 1 and plen == 1 and proto == b"\xcc" and alen == 4:
            out.append(".".join(str(x) for x in addr))
        # IPv6 (alen 16) intentionally ignored — walks are IPv4-only.
    return out


def _ipv6(b: bytes) -> str:
    parts = [f"{int.from_bytes(b[i:i+2], 'big'):x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def parse_cdp_frame(frame: bytes, source_interface: str = "?") -> NeighborDevice | None:
    """Parse a full Ethernet frame containing a CDP packet."""
    if len(frame) < 14:
        return None
    # Check either direct EtherType 0x2000 or SNAP-encapsulated
    body: bytes | None = None
    ethertype = int.from_bytes(frame[12:14], "big")
    if ethertype == 0x2000:
        body = frame[14:]
    elif frame[12:14] == b"\xaa\xaa" and len(frame) >= 22:
        # SNAP: 8 bytes of LLC/SNAP after ethernet header (dst6 src6 type2 = 14; then aa aa 03 00 00 0c 20 00)
        snap = frame[14:22]
        if snap == CDP_SNAP:
            body = frame[22:]
    if body is None:
        return None

    # CDP header: version(1) ttl(1) checksum(2)
    if len(body) < 4:
        return None
    ttl = body[1]
    payload = body[4:]

    dev = NeighborDevice(protocol="cdp", source_interface=source_interface)
    dev.raw_tlvs["ttl"] = ttl
    tlvs: dict = {}
    offset = 0
    while True:
        tlv = _read_tlv(payload, offset)
        if tlv is None:
            break
        tlv_type, _length, tlv_payload, offset = tlv
        tlvs[tlv_type] = tlv_payload
        if tlv_type == TLV_DEVICE_ID:
            dec = _decode_text(tlv_payload)
            dev.chassis_id = dec if dec else tlv_payload.hex()
            dev.system_name = dev.chassis_id
        elif tlv_type == TLV_PORT_ID:
            dev.port_id = _decode_port_id(tlv_payload) or tlv_payload.hex()
        elif tlv_type == TLV_SOFTWARE_VERSION:
            dev.system_description = _decode_text(tlv_payload) or ""
        elif tlv_type == TLV_PLATFORM:
            dev.platform = _decode_text(tlv_payload) or ""
        elif tlv_type == TLV_ADDRESSES:
            dev.management_ips = _addresses(tlv_payload)
        elif tlv_type == TLV_CAPABILITIES:
            dev.capabilities = _caps(tlv_payload)
        elif tlv_type == TLV_NATIVE_VLAN and len(tlv_payload) >= 2:
            dev.vlan = int.from_bytes(tlv_payload[:2], "big")
        elif tlv_type == TLV_DUPLEX and len(tlv_payload) >= 1:
            dev.raw_tlvs["duplex"] = tlv_payload[0]

    dev.raw_tlvs["tlv_types"] = sorted(tlvs.keys())
    if not dev.chassis_id and not dev.system_name:
        return None
    return dev
