"""LinkSight Upstream Discovery package.

SNMP-based upstream switch chain discovery with per-hop diagnostic data
(PVID, allowed VLANs, STP port state, negotiated link speed, neighbor identity).
"""

from .models import Hop, PortDiagnostics, UpstreamPath
from .classifier import classify_device, is_edge_device
from .snmp_client import SnmpClient
from .walker import UpstreamWalker

__all__ = [
    "Hop",
    "PortDiagnostics",
    "UpstreamPath",
    "classify_device",
    "is_edge_device",
    "SnmpClient",
    "UpstreamWalker",
]
