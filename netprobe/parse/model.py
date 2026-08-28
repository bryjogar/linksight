"""Core data model for NetProbe."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class NeighborDevice:
    """A device seen via LLDP or CDP on a local interface."""

    protocol: str                 # "lldp" | "cdp"
    source_interface: str         # local NIC that heard it
    chassis_id: str = ""
    chassis_id_type: int | None = None
    port_id: str = ""
    port_id_type: int | None = None
    system_name: str = ""
    system_description: str = ""
    platform: str = ""
    management_ips: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    vlan: int | None = None
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    raw_tlvs: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Dedup key: protocol + interface + chassis + port."""
        return (self.protocol, self.source_interface, self.chassis_id, self.port_id)

    def to_dict(self) -> dict:
        return asdict(self)

    def touch(self) -> None:
        self.last_seen = _now()
