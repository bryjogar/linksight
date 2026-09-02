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
    neighbor_port: str = ""
    neighbor_chassis: str = ""
    is_uplink: bool = False
    is_downlink: bool = False
    oper_status: str = "unknown"  # "up", "down", "testing", "unknown", "dormant", "notPresent", "lowerLayerDown"
    admin_status: str = "unknown"  # "up", "down", "testing"
    platform: str = ""

    def __post_init__(self) -> None:
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
