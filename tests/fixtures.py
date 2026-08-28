"""Byte-accurate LLDP/CDP frame fixtures (re-exported from netprobe.parse.builders)."""

from netprobe.parse.builders import (
    build_lldp_frame,
    build_cdp_frame,
    eth,
    LLDP_DST,
    CDP_DST,
)

LLDP_SAMPLE = build_lldp_frame()
CDP_SAMPLE = build_cdp_frame()
