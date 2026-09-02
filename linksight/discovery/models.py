"""Data models for Upstream Discovery."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class PortDiagnostics:
    """Per-port diagnostic data captured during discovery."""

    port_id: int | str
    port_name: str = ""
    pvid: int | None = None
    allowed_vlans: list[int] = field(default_factory=list)
    stp_state: str = "unknown"  # "forwarding", "blocking", "listening", "learning", "disabled", "broken", "unknown"
    link_speed_mbps: int | None = None
    is_root_port: bool = False
    neighbor_name: str = ""
    neighbor_ip: str = ""
    neighbor_port: str = ""
    is_uplink: bool = False
    is_downlink: bool = False
    oper_status: str = "unknown"  # "up", "down", "testing", "unknown", "dormant", "notPresent", "lowerLayerDown"
    admin_status: str = "unknown"  # "up", "down", "testing"

    def to_dict(self) -> dict:
        return asdict(self)

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
    status: str = "ok"  # "ok", "timeout", "unreachable", "auth_failed", "root_reached", "router_reached", "no_upstream", "ambiguous"
    error_message: str | None = None
    ports: list[PortDiagnostics] = field(default_factory=list)
    uplink_port: PortDiagnostics | None = None
    downlink_port: PortDiagnostics | None = None
    response_time_ms: float | None = None
    isp_gateway: str | None = None
    wan_interface: PortDiagnostics | None = None
    lan_interface: PortDiagnostics | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class UpstreamPath:
    """Complete upstream discovery result."""

    start_ip: str = ""
    hops: list[Hop] = field(default_factory=list)
    edge_type: str = "unknown"  # "stp_root", "router", "firewall", "gateway", "timeout", "unreachable", "no_upstream", "ambiguous"
    edge_summary: str = ""
    completed_at: str = field(default_factory=_now)
    success: bool = True

    def to_dict(self) -> dict:
        return asdict(self)
