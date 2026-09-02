"""LLDP (IEEE 802.1AB) TLV parser.

Frame format:
  Ethernet II: dst 01:80:c2:00:00:0e, src <mac>, EtherType 0x88CC
  LLDPDU: sequence of TLVs, each 2-byte header (7 bits type, 9 bits length)
          followed by payload; terminated by EndOfLLDPDU (type 0, length 0).
"""

from __future__ import annotations

from .model import NeighborDevice
from ..text_util import decode_text as _decode_text

LLDP_ETHERTYPE = 0x88CC
LLDP_MULTICAST = "01:80:c2:00:00:0e"

# TLV types
TLV_END = 0
TLV_CHASSIS_ID = 1
TLV_PORT_ID = 2
TLV_TTL = 3
TLV_PORT_DESCRIPTION = 4
TLV_SYSTEM_NAME = 5
TLV_SYSTEM_DESCRIPTION = 6
TLV_SYSTEM_CAPABILITIES = 7
TLV_MGMT_ADDRESS = 8
TLV_ORG_SPECIFIC = 127

CHASSIS_ID_TYPES = {
    4: "mac",
    5: "network-address",
    7: "locally-assigned",
}
PORT_ID_TYPES = {
    3: "mac",
    5: "interface-name",
    7: "locally-assigned",
}

CAPABILITY_BITS = [
    (0x0001, "Other"),
    (0x0002, "Repeater"),
    (0x0004, "Bridge"),
    (0x0008, "WLAN Access Point"),
    (0x0010, "Router"),
    (0x0020, "Telephone"),
    (0x0040, "DOCSIS Cable Device"),
    (0x0080, "Station Only"),
    (0x0100, "CVLAN"),
    (0x0200, "SVLAN"),
    (0x0400, "Two-port MAC Relay"),
]


def _read_tlv(buf: bytes, offset: int) -> tuple[int, int, bytes, int] | None:
    """Read one TLV at offset. Returns (tlv_type, length, payload, next_offset)."""
    if offset + 2 > len(buf):
        return None
    header = int.from_bytes(buf[offset : offset + 2], "big")
    tlv_type = (header >> 9) & 0x7F
    length = header & 0x01FF
    start = offset + 2
    end = start + length
    if end > len(buf):
        return None
    return tlv_type, length, buf[start:end], end


def _hex_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _caps(payload: bytes) -> list[str]:
    if len(payload) < 2:
        return []
    bits = int.from_bytes(payload[:2], "big")
    return [name for mask, name in CAPABILITY_BITS if bits & mask]


def _mgmt_addrs(payload: bytes) -> list[str]:
    """Parse Management Address TLV (802.1AB — length-first).

    Format per IEEE 802.1AB:
      management address string length (1)   <- includes subtype byte
      management address subtype (1)          (1=IPv4, 2=IPv6, ...)
      management address (N)
      interface numbering subtype (1)
      interface number (4)
      OID string length (1), OID string (M)
    """
    out: list[str] = []
    off = 0
    while off < len(payload):
        alen = payload[off]  # total: subtype byte + address bytes
        if alen == 0 or off + 1 + alen > len(payload):
            break
        subtype = payload[off + 1]
        addr = payload[off + 2 : off + 1 + alen]
        if subtype == 1 and len(addr) == 4:  # IPv4
            out.append(".".join(str(x) for x in addr))
        elif subtype == 2 and len(addr) == 16:  # IPv6
            out.append(_ipv6(addr))
        # skip address; then iface_subtype(1) + iface_num(4) + oid_len(1) + oid
        off += 1 + alen
        if off + 6 > len(payload):
            break
        oid_len = payload[off + 5]
        off += 6 + oid_len
    return out


def _ipv6(b: bytes) -> str:
    parts = [f"{int.from_bytes(b[i:i+2], 'big'):x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def parse_lldp_frame(frame: bytes, source_interface: str = "?") -> NeighborDevice | None:
    """Parse a full Ethernet frame containing an LLDPDU. Returns NeighborDevice or None."""
    # Ethernet header: 12 bytes (dst+src) + 2 EtherType
    if len(frame) < 14:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    if ethertype != LLDP_ETHERTYPE:
        return None
    payload = frame[14:]

    dev = NeighborDevice(protocol="lldp", source_interface=source_interface)
    tlvs: dict = {}
    offset = 0
    while True:
        tlv = _read_tlv(payload, offset)
        if tlv is None:
            break
        tlv_type, _length, tlv_payload, offset = tlv
        if tlv_type == TLV_END:
            break
        tlvs[tlv_type] = tlv_payload
        if tlv_type == TLV_CHASSIS_ID and len(tlv_payload) >= 1:
            st = tlv_payload[0]
            dev.chassis_id_type = st
            dev.chassis_id = CHASSIS_ID_TYPES.get(st, f"type-{st}")
            if st == 4 and len(tlv_payload) >= 7:
                dev.chassis_id = _hex_mac(tlv_payload[1:7])
            elif st in (5, 7) and len(tlv_payload) >= 2:
                dec = _decode_text(tlv_payload[1:])
                dev.chassis_id = dec if dec else tlv_payload[1:].hex()
            else:
                dev.chassis_id = tlv_payload[1:].hex()
        elif tlv_type == TLV_PORT_ID and len(tlv_payload) >= 1:
            st = tlv_payload[0]
            dev.port_id_type = st
            if st == 3 and len(tlv_payload) >= 7:
                dev.port_id = _hex_mac(tlv_payload[1:7])
            elif st in (5, 7) and len(tlv_payload) >= 2:
                dec = _decode_text(tlv_payload[1:])
                dev.port_id = dec if dec else tlv_payload[1:].hex()
            else:
                dev.port_id = tlv_payload[1:].hex()
        elif tlv_type == TLV_SYSTEM_NAME:
            dev.system_name = _decode_text(tlv_payload) or ""
        elif tlv_type == TLV_SYSTEM_DESCRIPTION:
            dev.system_description = _decode_text(tlv_payload) or ""
        elif tlv_type == TLV_PORT_DESCRIPTION:
            dev.raw_tlvs["port_description"] = _decode_text(tlv_payload) or ""
        elif tlv_type == TLV_SYSTEM_CAPABILITIES:
            dev.capabilities = _caps(tlv_payload)
        elif tlv_type == TLV_MGMT_ADDRESS:
            dev.management_ips = _mgmt_addrs(tlv_payload)
        elif tlv_type == TLV_ORG_SPECIFIC and len(tlv_payload) >= 5:
            oui = tlv_payload[:3]
            subtype = tlv_payload[3]
            value = tlv_payload[4:]
            if oui == b"\x00\x80\xc2" and subtype == 1 and len(value) >= 2:  # Port VLAN ID
                dev.vlan = int.from_bytes(value[:2], "big")

    dev.raw_tlvs["tlv_types"] = sorted(tlvs.keys())
    if not dev.chassis_id and not dev.system_name:
        return None
    if not dev.platform:
        dev.platform = extract_platform(dev.system_description)
    return dev


def extract_platform(system_description: str) -> str:
    """Best-effort model/platform from an LLDP System Description.

    Vendors embed the model early in the string, usually before a comma,
    'revision', 'Version', 'Software', or '(c)'. Examples:
      "HP J9729A 2920-48G-POE+ Switch, revision WB.16.10.0010, ..." -> "HP J9729A 2920-48G-POE+ Switch"
      "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), ..." -> "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M)"
    """
    if not system_description:
        return ""
    s = system_description.strip()
    if len(s) <= 64:
        return s
    # cut at the first of the usual "detail starts here" markers
    for marker in (", revision", ", Version", ", version", " Software (", " (c)"):
        idx = s.find(marker)
        if idx > 0:
            candidate = s[:idx]
            # keep the closing paren for the "Software (X)" case
            if marker == " Software (":
                close = s.find(")", idx)
                if close > 0:
                    candidate = s[: close + 1]
            if len(candidate) <= 80:
                return candidate
    return s[:64] + "…"
