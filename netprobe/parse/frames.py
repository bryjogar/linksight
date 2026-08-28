"""Frame dispatch: raw Ethernet frame bytes -> protocol parser."""

from __future__ import annotations

from .model import NeighborDevice
from .lldp import parse_lldp_frame, LLDP_ETHERTYPE
from .cdp import parse_cdp_frame, CDP_SNAP


def parse_frame(frame: bytes, source_interface: str = "?") -> NeighborDevice | None:
    """Dispatch a raw Ethernet frame to the right parser by its type.

    Returns a NeighborDevice for LLDP/CDP frames, None for anything else.
    """
    if len(frame) < 14:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    if ethertype == LLDP_ETHERTYPE:
        return parse_lldp_frame(frame, source_interface)
    if ethertype == 0x2000:
        return parse_cdp_frame(frame, source_interface)
    # SNAP-encapsulated CDP
    if frame[12:14] == b"\xaa\xaa" and frame[14:22] == CDP_SNAP:
        return parse_cdp_frame(frame, source_interface)
    return None
