"""Data models for Upstream Discovery."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from ..text_util import (
    decode_text,
    decode_port_id,
    format_mac,
    decode_ip_address,
    is_printable_text,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _prefer_ipv4(ips: list[str]) -> str:
    """Pick the preferred management address: first IPv4 (link-local 169.254
    excluded), else empty. IPv6 is never chosen — walks are IPv4-only."""
    for ip in ips:
        if ":" not in ip and not ip.lower().startswith("169.254."):
            return ip
    return ""


def _ipv4_network(ip: str, prefix: int) -> str | None:
    """Network address string for an IPv4 and prefix, or None on failure."""
    import ipaddress

    try:
        return str(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False).network_address)
    except Exception:
        return None


def _prefer_onlink_ip(ips: list[str], context_ip: str) -> str:
    """Among IPv4 management candidates, prefer the one on-link with the walk
    context: same /24 first, then same /16. Fall back to the first usable
    IPv4. Never returns IPv6."""
    v4 = [ip for ip in ips if ":" not in ip and not ip.lower().startswith("169.254.")]
    if not v4:
        return ""
    if context_ip:
        ctx24 = _ipv4_network(context_ip, 24)
        if ctx24:
            for ip in v4:
                if _ipv4_network(ip, 24) == ctx24:
                    return ip
        ctx16 = _ipv4_network(context_ip, 16)
        if ctx16:
            for ip in v4:
                if _ipv4_network(ip, 16) == ctx16:
                    return ip
    return v4[0]


@dataclass
class PortDiagnostics:
    """Per-port diagnostic data captured during discovery."""

    port_id: int | str
    port_name: str = ""
    pvid: int | None = None
    allowed_vlans: list[int] = field(default_factory=list)
    tagged_vlans: list[int] = field(default_factory=list)
    untagged_vlans: list[int] = field(default_factory=list)
    stp_state: str = "unknown"  # "forwarding", "blocking", "listening", "learning", "disabled", "broken", "unknown"
    link_speed_mbps: int | None = None
    is_root_port: bool = False
    neighbor_name: str = ""
    neighbor_ip: str = ""
    neighbor_ips: list[str] = field(default_factory=list)
    neighbor_port: str = ""
    neighbor_chassis: str = ""
    is_uplink: bool = False
    is_downlink: bool = False
    oper_status: str = "unknown"  # "up", "down", "testing", "unknown", "dormant", "notPresent", "lowerLayerDown"
    admin_status: str = "unknown"  # "up", "down", "testing"
    platform: str = ""

    def __post_init__(self) -> None:
        # Normalize port_id (bytes/reprs can leak into "Port b'...'")
        if isinstance(self.port_id, (bytes, bytearray)):
            self.port_id = decode_port_id(self.port_id)
        elif isinstance(self.port_id, str):
            s = self.port_id.strip()
            if (s.startswith("b'") and s.endswith("'")) or (s.startswith('b"') and s.endswith('"')):
                s = decode_port_id(s) or ""
            elif not is_printable_text(s):
                s = ""
            if s.isdigit():
                self.port_id = int(s)
            else:
                self.port_id = s

        # Normalize port_name
        if isinstance(self.port_name, (bytes, bytearray)):
            dec = decode_text(self.port_name)
            self.port_name = dec if dec else f"Port {self.port_id}"
        elif isinstance(self.port_name, str):
            if "b'" in self.port_name or 'b"' in self.port_name:
                dec = decode_text(self.port_name)
                self.port_name = dec if dec else f"Port {self.port_id}"
            elif not is_printable_text(self.port_name):
                self.port_name = f"Port {self.port_id}"
            else:
                self.port_name = self.port_name.strip()
        elif self.port_name is not None:
            self.port_name = str(self.port_name)
        else:
            self.port_name = f"Port {self.port_id}"

        # Normalize neighbor_chassis
        if isinstance(self.neighbor_chassis, (bytes, bytearray)):
            self.neighbor_chassis = format_mac(self.neighbor_chassis)
        elif isinstance(self.neighbor_chassis, str):
            if "b'" in self.neighbor_chassis or 'b"' in self.neighbor_chassis:
                self.neighbor_chassis = format_mac(self.neighbor_chassis)
            elif not is_printable_text(self.neighbor_chassis):
                self.neighbor_chassis = ""
            else:
                self.neighbor_chassis = self.neighbor_chassis.strip()
        else:
            self.neighbor_chassis = ""

        # Normalize neighbor_name
        from .arp_resolve import normalize_mac
        fallback_name = self.neighbor_chassis if (self.neighbor_chassis and normalize_mac(self.neighbor_chassis)) else ""
        if isinstance(self.neighbor_name, (bytes, bytearray)):
            dec = decode_text(self.neighbor_name)
            self.neighbor_name = dec if dec else fallback_name
        elif isinstance(self.neighbor_name, str):
            if "b'" in self.neighbor_name or 'b"' in self.neighbor_name:
                dec = decode_text(self.neighbor_name)
                self.neighbor_name = dec if dec else fallback_name
            elif not is_printable_text(self.neighbor_name):
                self.neighbor_name = fallback_name
            else:
                self.neighbor_name = self.neighbor_name.strip()
        else:
            self.neighbor_name = fallback_name

        # Normalize neighbor_port
        if isinstance(self.neighbor_port, (bytes, bytearray)):
            self.neighbor_port = decode_port_id(self.neighbor_port)
        elif isinstance(self.neighbor_port, str):
            if "b'" in self.neighbor_port or 'b"' in self.neighbor_port:
                self.neighbor_port = decode_port_id(self.neighbor_port)
            elif not is_printable_text(self.neighbor_port):
                self.neighbor_port = ""
            else:
                self.neighbor_port = self.neighbor_port.strip()
        elif isinstance(self.neighbor_port, (int, float)) and not isinstance(self.neighbor_port, bool):
            self.neighbor_port = str(self.neighbor_port)
        else:
            self.neighbor_port = ""

        # Normalize neighbor_ip
        if isinstance(self.neighbor_ip, (bytes, bytearray)):
            self.neighbor_ip = decode_ip_address(self.neighbor_ip) or ""
        elif isinstance(self.neighbor_ip, str):
            if "b'" in self.neighbor_ip or 'b"' in self.neighbor_ip:
                self.neighbor_ip = decode_ip_address(self.neighbor_ip) or ""
            elif not is_printable_text(self.neighbor_ip):
                self.neighbor_ip = ""
            else:
                self.neighbor_ip = self.neighbor_ip.strip()
        else:
            self.neighbor_ip = ""

        # Normalize neighbor_ips list (dedupe, drop empties), then keep neighbor_ip
        # in sync with the preferred address when the list is authoritative.
        if isinstance(self.neighbor_ips, (bytes, bytearray)):
            dec = decode_ip_address(self.neighbor_ips)
            self.neighbor_ips = [dec] if dec else []
        elif isinstance(self.neighbor_ips, str):
            dec = decode_ip_address(self.neighbor_ips)
            self.neighbor_ips = [dec] if dec else []
        elif not isinstance(self.neighbor_ips, (list, tuple)):
            self.neighbor_ips = []
        cleaned_ips: list[str] = []
        for ip in self.neighbor_ips:
            dec = decode_ip_address(ip)
            if dec and dec not in cleaned_ips:
                cleaned_ips.append(dec)
        self.neighbor_ips = cleaned_ips
        # The list is authoritative: always resync the single field to the
        # preferred IPv4. A pre-set IPv6 (or stale address) must not survive.
        if self.neighbor_ips:
            self.neighbor_ip = _prefer_ipv4(self.neighbor_ips)
        elif self.neighbor_ip and self.neighbor_ip not in self.neighbor_ips:
            self.neighbor_ips.insert(0, self.neighbor_ip)
        # IPv6 is never a management/walk address — clear any that remains.
        if ":" in self.neighbor_ip:
            self.neighbor_ip = ""

        # Normalize platform
        if isinstance(self.platform, (bytes, bytearray)):
            self.platform = decode_text(self.platform) or ""
        elif isinstance(self.platform, str):
            if "b'" in self.platform or 'b"' in self.platform:
                self.platform = decode_text(self.platform) or ""
            elif not is_printable_text(self.platform):
                self.platform = ""
            else:
                self.platform = self.platform.strip()
        else:
            self.platform = ""

        # Normalize status fields
        for field_name in ("stp_state", "oper_status", "admin_status"):
            val = getattr(self, field_name)
            if isinstance(val, (bytes, bytearray)):
                dec = decode_text(val)
                setattr(self, field_name, dec if dec else "unknown")
            elif isinstance(val, str):
                if "b'" in val or 'b"' in val or not is_printable_text(val):
                    setattr(self, field_name, "unknown")
            elif not isinstance(val, str):
                setattr(self, field_name, "unknown")

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def effective_pvid(self) -> int | None:
        """Effective PVID: dot1qPvid if set (>0), else fallback to first untagged VLAN for display."""
        if self.pvid is not None and self.pvid > 0:
            return self.pvid
        if self.untagged_vlans:
            return self.untagged_vlans[0]
        return None

    @property
    def is_healthy_speed(self) -> bool:
        """True if link speed is at least 1000 Mbps (Gigabit) or unset."""
        if self.link_speed_mbps is None:
            return True
        return self.link_speed_mbps >= 1000

    @property
    def is_forwarding(self) -> bool:
        return self.stp_state.lower() == "forwarding"

    @property
    def is_oper_up(self) -> bool:
        return self.oper_status.lower() == "up"


@dataclass
class Hop:
    """A single switch or edge device along the upstream path."""

    hop_index: int = 1
    hostname: str = ""
    mgmt_ip: str = ""
    sys_descr: str = ""
    platform: str = ""
    device_type: str = "switch"  # "switch", "router", "firewall", "gateway", "edge", "unknown"
    is_stp_root: bool = False
    stp_root_bridge_id: str = ""
    stp_bridge_id: str = ""
    stp_root_port_num: int | None = None
    default_gateway: str | None = None
    status: str = "ok"  # "ok", "timeout", "unreachable", "auth_failed", "root_reached", "router_reached", "no_upstream", "ambiguous", "root_claimed_but_uplinks_present"
    error_message: str | None = None
    ports: list[PortDiagnostics] = field(default_factory=list)
    uplink_port: PortDiagnostics | None = None
    downlink_port: PortDiagnostics | None = None
    response_time_ms: float | None = None
    isp_gateway: str | None = None
    wan_interface: PortDiagnostics | None = None
    lan_interface: PortDiagnostics | None = None
    ambiguous_candidates: list[PortDiagnostics] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.hostname, (bytes, bytearray)):
            dec = decode_text(self.hostname)
            self.hostname = dec if dec else self.mgmt_ip
        elif isinstance(self.hostname, str):
            if "b'" in self.hostname or 'b"' in self.hostname or not is_printable_text(self.hostname):
                dec = decode_text(self.hostname)
                self.hostname = dec if dec else self.mgmt_ip
        elif not isinstance(self.hostname, str):
            self.hostname = self.mgmt_ip

        if isinstance(self.sys_descr, (bytes, bytearray)):
            self.sys_descr = decode_text(self.sys_descr) or ""
        elif isinstance(self.sys_descr, str):
            if "b'" in self.sys_descr or 'b"' in self.sys_descr or not is_printable_text(self.sys_descr):
                self.sys_descr = decode_text(self.sys_descr) or ""
        else:
            self.sys_descr = ""

        if isinstance(self.platform, (bytes, bytearray)):
            self.platform = decode_text(self.platform) or ""
        elif isinstance(self.platform, str):
            if "b'" in self.platform or 'b"' in self.platform or not is_printable_text(self.platform):
                self.platform = decode_text(self.platform) or ""
        else:
            self.platform = ""

        if self.stp_root_bridge_id:
            self.stp_root_bridge_id = format_mac(self.stp_root_bridge_id)
        if self.stp_bridge_id:
            self.stp_bridge_id = format_mac(self.stp_bridge_id)

        if self.default_gateway:
            self.default_gateway = decode_ip_address(self.default_gateway)
        if self.isp_gateway:
            self.isp_gateway = decode_ip_address(self.isp_gateway)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class UpstreamPath:
    """Complete upstream discovery result."""

    start_ip: str = ""
    hops: list[Hop] = field(default_factory=list)
    edge_type: str = "unknown"  # "stp_root", "router", "firewall", "gateway", "timeout", "unreachable", "no_upstream", "ambiguous", "root_claimed_but_uplinks_present"
    edge_summary: str = ""
    completed_at: str = field(default_factory=_now)
    success: bool = True

    def to_dict(self) -> dict:
        return asdict(self)
