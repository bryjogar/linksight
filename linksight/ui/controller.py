"""LinkSight application controller: wires capture source -> UI state.

In-memory only — LinkSight is a readout, not a data collector. The latest
observed LAN/switch facts are held here and pushed to the widgets via Qt
signals.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from ..parse.model import NeighborDevice
from ..discovery.models import UpstreamPath


class AppController(QObject):
    """Holds the latest observed state and capture source."""

    device_seen = Signal(object, object)  # (NeighborDevice, raw_bytes)
    dhcp_seen = Signal(object, object)    # (DhcpObservation, raw_bytes)
    capture_error = Signal(str)
    capture_state_changed = Signal(bool)  # True = running
    upstream_discovery_started = Signal(str)
    upstream_discovery_progress = Signal(str)
    upstream_discovery_finished = Signal(object)  # UpstreamPath

    def __init__(self):
        super().__init__()
        self.source = None  # Sniffer or DemoSource, set by main_window
        self.switch: NeighborDevice | None = None   # latest LLDP/CDP neighbor
        self.network: dict = {}                     # observed DHCP facts
        self.upstream_path: UpstreamPath | None = None
        self.frames: int = 0

    def on_device(self, dev: NeighborDevice, raw: bytes | None = None) -> None:
        self.switch = dev
        self.frames += 1
        self.device_seen.emit(dev, raw)

    def on_dhcp(self, obs, raw: bytes | None = None) -> None:
        d = obs.to_dict()
        if obs.is_reply:
            for k in ("offered_ip", "server_ip", "subnet_mask", "lease_seconds", "domain"):
                if d.get(k):
                    self.network[k] = d[k]
            if d.get("gateways"):
                self.network["gateways"] = d["gateways"]
            if d.get("dns_servers"):
                self.network["dns_servers"] = d["dns_servers"]
        self.network["last_message"] = d.get("message_type", "")
        self.dhcp_seen.emit(obs, raw)

    def on_error(self, msg: str) -> None:
        self.capture_error.emit(msg)

    def on_upstream_started(self, start_ip: str) -> None:
        self.upstream_discovery_started.emit(start_ip)

    def on_upstream_progress(self, msg: str) -> None:
        self.upstream_discovery_progress.emit(msg)

    def on_upstream_finished(self, path: UpstreamPath) -> None:
        self.upstream_path = path
        self.upstream_discovery_finished.emit(path)

    def close(self) -> None:
        if self.source:
            self.source.stop()
