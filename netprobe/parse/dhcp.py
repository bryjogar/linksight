"""DHCP (BOOTP) parser — passive observation of DHCP traffic on the wire.

We don't take a lease (that would require privileges and disturb the port).
Instead we listen for the DHCP OFFER/ACK the adapter's own DHCP transaction
generates and extract the network facts Netool displays: offered IP, subnet
mask, gateway, DNS servers, lease time, and DHCP server identity.

Packet format (RFC 2131):
  BOOTP header (fixed 236 bytes) + magic cookie 63 82 53 63 + options.
  Options: code(1) len(1) value...; 255 = end; 53 = message type;
           1 = subnet mask, 3 = router, 6 = DNS, 51 = lease time,
           54 = server identifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DHCP_MAGIC = b"\x63\x82\x53\x63"

# Message types (option 53)
MSG_DISCOVER = 1
MSG_OFFER = 2
MSG_REQUEST = 3
MSG_DECLINE = 4
MSG_ACK = 5
MSG_NAK = 6
MSG_RELEASE = 7
MSG_INFORM = 8

MSG_NAMES = {
    MSG_DISCOVER: "DISCOVER",
    MSG_OFFER: "OFFER",
    MSG_REQUEST: "REQUEST",
    MSG_DECLINE: "DECLINE",
    MSG_ACK: "ACK",
    MSG_NAK: "NAK",
    MSG_RELEASE: "RELEASE",
    MSG_INFORM: "INFORM",
}

# option codes
OPT_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_LEASE = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_DOMAIN = 15


@dataclass
class DhcpObservation:
    """Facts learned from one DHCP reply (OFFER or ACK)."""

    message_type: str = ""
    xid: int = 0
    client_mac: str = ""
    offered_ip: str = ""
    server_ip: str = ""
    subnet_mask: str = ""
    gateways: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    lease_seconds: int = 0
    domain: str = ""

    @property
    def is_reply(self) -> bool:
        return self.message_type in ("OFFER", "ACK")

    def to_dict(self) -> dict:
        return {
            "message_type": self.message_type,
            "xid": self.xid,
            "client_mac": self.client_mac,
            "offered_ip": self.offered_ip,
            "server_ip": self.server_ip,
            "subnet_mask": self.subnet_mask,
            "gateways": self.gateways,
            "dns_servers": self.dns_servers,
            "lease_seconds": self.lease_seconds,
            "domain": self.domain,
        }


def _ip4(b: bytes) -> str:
    if len(b) != 4:
        return ""
    return ".".join(str(x) for x in b)


def _parse_options(opts: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    i = 0
    while i < len(opts):
        code = opts[i]
        if code == 0:  # pad
            i += 1
            continue
        if code == 255:  # end
            break
        if i + 1 >= len(opts):
            break
        length = opts[i + 1]
        if i + 2 + length > len(opts):
            break
        out.append((code, opts[i + 2 : i + 2 + length]))
        i += 2 + length
    return out


def parse_dhcp(payload: bytes, src_ip: str = "", dst_ip: str = "") -> DhcpObservation | None:
    """Parse a DHCP packet body (UDP payload). Returns None if not DHCP."""
    if len(payload) < 240:
        return None
    if payload[236:240] != DHCP_MAGIC:
        return None

    obs = DhcpObservation()
    obs.xid = int.from_bytes(payload[4:8], "big")
    obs.client_mac = ":".join(f"{payload[28 + i]:02x}" for i in range(6) if payload[28 + i] or i < 6)[:17]
    obs.offered_ip = _ip4(payload[16:20])  # yiaddr
    obs.server_ip = _ip4(payload[20:24])   # siaddr (next server) — often empty

    for code, value in _parse_options(payload[240:]):
        if code == OPT_MSG_TYPE and len(value) >= 1:
            obs.message_type = MSG_NAMES.get(value[0], f"type-{value[0]}")
        elif code == OPT_MASK:
            obs.subnet_mask = _ip4(value)
        elif code == OPT_ROUTER:
            obs.gateways = [_ip4(value[i : i + 4]) for i in range(0, len(value) - 3, 4) if _ip4(value[i : i + 4])]
        elif code == OPT_DNS:
            obs.dns_servers = [_ip4(value[i : i + 4]) for i in range(0, len(value) - 3, 4) if _ip4(value[i : i + 4])]
        elif code == OPT_LEASE and len(value) >= 4:
            obs.lease_seconds = int.from_bytes(value[:4], "big")
        elif code == OPT_SERVER_ID:
            obs.server_ip = _ip4(value)  # authoritative DHCP server
        elif code == OPT_DOMAIN:
            obs.domain = value.decode("utf-8", "replace")

    # Fallback: server IP from source of the packet if option 54 absent
    if not obs.server_ip and src_ip:
        obs.server_ip = src_ip

    if not obs.message_type:
        return None
    return obs
